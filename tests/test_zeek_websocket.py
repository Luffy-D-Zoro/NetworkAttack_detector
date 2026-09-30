from __future__ import annotations

import copy
import importlib.util
import io
import json
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path

from src.coordinator import StreamingCoordinator
from src.flow.flow_manager import FlowManager
from src.ingestion.zeek_websocket import (
    DEFAULT_TOPIC,
    EVENT_NAME,
    SnapshotValidationError,
    TcpConnectionSignal,
    decode_flow_snapshot,
    decode_stream_event,
    iter_snapshots,
    validate_ack,
    websocket_uri,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
POLICY = PROJECT_ROOT / "zeek" / "flow_stream.zeek"
TEST_PCAP = Path("/usr/share/btest/data/pcaps/conn-size.trace")


def typed(data_type: str, data: object) -> dict[str, object]:
    return {"@data-type": data_type, "data": data}


def valid_message() -> dict[str, object]:
    args = [
        typed("count", 1),
        typed("string", "update"),
        typed("timestamp", "2026-09-30T12:00:02.000"),
        typed("string", "C123example"),
        typed("address", "192.0.2.10"),
        typed("count", 50000),
        typed("address", "2001:db8::53"),
        typed("count", 53),
        typed("count", 17),
        typed("timestamp", "2026-09-30T12:00:00.000"),
        typed("timestamp", "2026-09-30T12:00:01.500"),
        typed("count", 3),
        typed("count", 240),
        typed("count", 156),
        typed("count", 2),
        typed("count", 320),
        typed("count", 236),
        typed("count", 1),
        typed("count", 1),
        typed("string", "Dd"),
    ]
    metadata = typed(
        "vector",
        [
            typed(
                "vector",
                [
                    typed("count", 1),
                    typed("timestamp", "2026-09-30T12:00:02.000"),
                ],
            )
        ],
    )
    event = typed(
        "vector",
        [typed("string", EVENT_NAME), typed("vector", args), metadata],
    )
    return {
        "type": "data-message",
        "topic": DEFAULT_TOPIC,
        "@data-type": "vector",
        "data": [typed("count", 1), typed("count", 1), event],
    }


def encoded_message() -> str:
    return json.dumps(valid_message())


class FakeWebSocket:
    def __init__(self, messages: list[str]):
        self.messages = iter(messages)
        self.sent: list[str] = []

    def __enter__(self) -> FakeWebSocket:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def send(self, message: str) -> None:
        self.sent.append(message)

    def recv(self, timeout: float | None = None) -> str:
        del timeout
        try:
            return next(self.messages)
        except StopIteration as exc:
            raise OSError("connection closed") from exc


class SnapshotDecoderTests(unittest.TestCase):
    def test_valid_snapshot_is_decoded(self) -> None:
        snapshot = decode_flow_snapshot(encoded_message())

        self.assertEqual(snapshot.schema_version, 1)
        self.assertEqual(snapshot.kind, "update")
        self.assertEqual(str(snapshot.orig_h), "192.0.2.10")
        self.assertEqual(str(snapshot.resp_h), "2001:db8::53")
        self.assertEqual(snapshot.orig_pkts, 3)
        self.assertEqual(snapshot.resp_ip_bytes, 320)
        self.assertEqual(snapshot.history, "Dd")
        self.assertEqual(snapshot.to_dict()["observed_at"], "2026-09-30T12:00:02Z")

    def test_acknowledgement_is_strictly_validated(self) -> None:
        ack = validate_ack(
            json.dumps({"type": "ack", "endpoint": "endpoint-1", "version": "8.0.6"})
        )
        self.assertEqual(ack["endpoint"], "endpoint-1")

        with self.assertRaises(SnapshotValidationError):
            validate_ack(json.dumps({"type": "ack", "endpoint": "endpoint-1"}))

    def test_optional_transport_metadata_may_be_absent(self) -> None:
        message = valid_message()
        message["data"][2]["data"].pop()

        snapshot = decode_flow_snapshot(json.dumps(message))

        self.assertEqual(snapshot.uid, "C123example")

    def test_schema_deviations_are_rejected(self) -> None:
        cases: list[tuple[str, Callable[[dict[str, object]], None]]] = [
            ("wrong topic", lambda m: m.update(topic="wrong/topic")),
            ("extra key", lambda m: m.update(extra=True)),
            ("wrong format", lambda m: m["data"][0].update(data=2)),
            (
                "wrong event",
                lambda m: m["data"][2]["data"][0].update(data="Other::event"),
            ),
            (
                "unsupported schema",
                lambda m: m["data"][2]["data"][1]["data"][0].update(data=2),
            ),
            (
                "invalid kind",
                lambda m: m["data"][2]["data"][1]["data"][1].update(data="packet"),
            ),
            (
                "invalid address",
                lambda m: m["data"][2]["data"][1]["data"][4].update(data="bad-ip"),
            ),
            (
                "negative count",
                lambda m: m["data"][2]["data"][1]["data"][11].update(data=-1),
            ),
        ]

        for label, mutate in cases:
            with self.subTest(label=label):
                message = copy.deepcopy(valid_message())
                mutate(message)
                with self.assertRaises(SnapshotValidationError):
                    decode_flow_snapshot(json.dumps(message))

    def test_reconnects_after_network_failure(self) -> None:
        calls = 0
        websocket = FakeWebSocket(
            [
                json.dumps({"type": "ack", "endpoint": "endpoint-1", "version": "8.0.6"}),
                encoded_message(),
            ]
        )

        def connector(uri: str, **kwargs: object) -> FakeWebSocket:
            nonlocal calls
            del uri, kwargs
            calls += 1
            if calls == 1:
                raise OSError("not ready")
            return websocket

        delays: list[float] = []
        errors = io.StringIO()
        snapshots = iter_snapshots(
            websocket_uri("127.0.0.1", 9997),
            connector=connector,
            reconnect_initial=0.25,
            reconnect_max=1.0,
            sleep=delays.append,
            error_stream=errors,
        )
        try:
            snapshot = next(snapshots)
        finally:
            snapshots.close()

        self.assertEqual(snapshot.uid, "C123example")
        self.assertEqual(calls, 2)
        self.assertEqual(delays, [0.25])
        self.assertEqual(json.loads(websocket.sent[0]), [DEFAULT_TOPIC])
        self.assertIn("retrying", errors.getvalue())

    def test_invalid_data_message_is_skipped(self) -> None:
        bad = valid_message()
        bad["topic"] = "wrong/topic"
        websocket = FakeWebSocket(
            [
                json.dumps({"type": "ack", "endpoint": "endpoint-1", "version": "8.0.6"}),
                json.dumps(bad),
                encoded_message(),
            ]
        )
        errors = io.StringIO()
        snapshots = iter_snapshots(
            websocket_uri("127.0.0.1", 9997),
            connector=lambda *args, **kwargs: websocket,
            sleep=lambda delay: None,
            error_stream=errors,
        )
        try:
            snapshot = next(snapshots)
        finally:
            snapshots.close()

        self.assertEqual(snapshot.uid, "C123example")
        self.assertIn("Rejected", errors.getvalue())


@unittest.skipUnless(
    shutil.which("zeek") and TEST_PCAP.exists() and importlib.util.find_spec("websockets"),
    "requires Zeek, its packaged test PCAP, and the websockets dependency",
)
class ZeekWebSocketIntegrationTests(unittest.TestCase):
    def test_zeek_publishes_a_decodable_snapshot(self) -> None:
        from websockets.sync.client import connect

        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]

        with tempfile.TemporaryDirectory() as output_dir:
            helper = Path(output_dir) / "integration-helper.zeek"
            helper.write_text(
                """\
module FlowStream;

global integration_connections: table[string] of connection;

event new_connection(c: connection) &priority=-2
    {
    integration_connections[c$uid] = c;
    }

event Cluster::websocket_client_added(endpoint: Cluster::EndpointInfo,
                                      subscriptions: string_vec) &priority=-1
    {
    for ( uid in integration_connections )
        {
        if ( integration_connections[uid]$id$proto != 6 )
            next;
        publish_connection(integration_connections[uid], "update");
        publish_tcp_signal(integration_connections[uid], "syn_start", "unknown");
        return;
        }
    }
""",
                encoding="utf-8",
            )
            process = subprocess.Popen(
                [
                    "zeek",
                    "-C",
                    "-r",
                    str(TEST_PCAP),
                    str(POLICY),
                    str(helper),
                    f"FlowStream::listen_port={port}/tcp",
                    "FlowStream::snapshot_interval=1sec",
                ],
                cwd=output_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                uri = websocket_uri("127.0.0.1", port)
                websocket = None
                deadline = time.monotonic() + 10
                while websocket is None and time.monotonic() < deadline:
                    try:
                        websocket = connect(uri, open_timeout=0.5, close_timeout=0.5)
                    except OSError:
                        time.sleep(0.05)
                self.assertIsNotNone(websocket, "Zeek WebSocket listener did not start")

                with websocket:
                    websocket.send(json.dumps([DEFAULT_TOPIC]))
                    validate_ack(websocket.recv(timeout=2))
                    snapshot = decode_flow_snapshot(websocket.recv(timeout=5))
                    tcp_signal = decode_stream_event(websocket.recv(timeout=5))

                self.assertIn(snapshot.kind, {"open", "update", "final"})
                self.assertTrue(snapshot.uid)
                self.assertGreaterEqual(snapshot.orig_pkts + snapshot.resp_pkts, 1)
                self.assertIsInstance(tcp_signal, TcpConnectionSignal)
                self.assertEqual(tcp_signal.kind, "syn_start")

                manager = FlowManager(
                    inactivity_timeout=timedelta(seconds=120),
                    cleanup_interval=timedelta(seconds=5),
                )
                coordinator = StreamingCoordinator(
                    flow_manager=manager,
                    correlation_timeout=timedelta(seconds=300),
                )
                result = coordinator.process(snapshot)
                signal_result = coordinator.process(tcp_signal)
                updates = result.updates
                self.assertGreaterEqual(len(updates), 1)
                self.assertGreaterEqual(len(manager), 1)
                self.assertTrue(signal_result.tcp_signal_accepted)
                self.assertGreaterEqual(len(coordinator.ddos_manager), 1)
                self.assertGreaterEqual(len(coordinator.scan_manager), 1)
            finally:
                process.terminate()
                try:
                    stdout, stderr = process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    stdout, stderr = process.communicate(timeout=5)

            self.assertNotIn("fatal error", stderr.lower(), msg=stdout + stderr)


if __name__ == "__main__":
    unittest.main()
