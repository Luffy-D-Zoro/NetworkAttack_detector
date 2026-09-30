"""Receive and strictly dispatch FlowStream events from Zeek's WebSocket API."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys
import time
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any, TextIO

SCHEMA_VERSION = 1
FLOW_SNAPSHOT_EVENT = "FlowStream::flow_snapshot"
TCP_SIGNAL_EVENT = "FlowStream::tcp_connection_signal"
# Phase 1 callers imported this name directly.
EVENT_NAME = FLOW_SNAPSHOT_EVENT
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9997
DEFAULT_TOPIC = "sih/flow/v1"
WEBSOCKET_PATH = "/v1/messages/json"
VALID_KINDS = frozenset({"open", "update", "flipped", "final"})
VALID_TCP_SIGNAL_KINDS = frozenset(
    {"syn_start", "established", "attempt_timeout", "rejected", "reset"}
)
VALID_ACTOR_ROLES = frozenset({"orig", "resp", "unknown"})
MAX_COUNT = (1 << 64) - 1

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
Connector = Callable[..., AbstractContextManager[Any]]


class SnapshotValidationError(ValueError):
    """A WebSocket message does not match an approved strict event schema."""


@dataclass(frozen=True, slots=True)
class FlowSnapshot:
    """One cumulative, bidirectional Zeek connection snapshot."""

    schema_version: int
    kind: str
    observed_at: datetime
    uid: str
    orig_h: IPAddress
    orig_p: int
    resp_h: IPAddress
    resp_p: int
    ip_proto: int
    first_seen: datetime
    last_seen: datetime
    orig_pkts: int
    orig_ip_bytes: int
    orig_payload_bytes: int
    resp_pkts: int
    resp_ip_bytes: int
    resp_payload_bytes: int
    orig_state: int
    resp_state: int
    history: str

    def to_dict(self) -> dict[str, object]:
        result = asdict(self)
        result["observed_at"] = _format_timestamp(self.observed_at)
        result["first_seen"] = _format_timestamp(self.first_seen)
        result["last_seen"] = _format_timestamp(self.last_seen)
        result["orig_h"] = str(self.orig_h)
        result["resp_h"] = str(self.resp_h)
        return result


@dataclass(frozen=True, slots=True)
class TcpConnectionSignal:
    """One connection-level TCP semantic signal emitted by Zeek."""

    schema_version: int
    event_time: datetime
    zeek_uid: str
    kind: str
    orig_h: IPAddress
    orig_p: int
    resp_h: IPAddress
    resp_p: int
    ip_protocol: int
    actor_role: str

    def to_dict(self) -> dict[str, object]:
        result = asdict(self)
        result["event_time"] = _format_timestamp(self.event_time)
        result["orig_h"] = str(self.orig_h)
        result["resp_h"] = str(self.resp_h)
        return result


StreamEvent = FlowSnapshot | TcpConnectionSignal


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _json_object(raw: str | bytes, label: str) -> dict[str, Any]:
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SnapshotValidationError(f"{label} is not valid UTF-8") from exc
    if not isinstance(raw, str):
        raise SnapshotValidationError(f"{label} must be text")

    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SnapshotValidationError(f"{label} is not valid JSON") from exc

    if not isinstance(value, dict):
        raise SnapshotValidationError(f"{label} must be a JSON object")
    return value


def _exact_keys(value: dict[str, Any], expected: set[str], path: str) -> None:
    actual = set(value)
    if actual != expected:
        raise SnapshotValidationError(
            f"{path} keys must be {sorted(expected)}, got {sorted(actual)}"
        )


def _typed(value: object, expected_type: str, path: str) -> Any:
    if not isinstance(value, dict):
        raise SnapshotValidationError(f"{path} must be a typed object")
    _exact_keys(value, {"@data-type", "data"}, path)
    if value["@data-type"] != expected_type:
        raise SnapshotValidationError(
            f"{path} must have type {expected_type!r}, got {value['@data-type']!r}"
        )
    return value["data"]


def _vector(value: object, path: str) -> list[Any]:
    result = _typed(value, "vector", path)
    if not isinstance(result, list):
        raise SnapshotValidationError(f"{path}.data must be a list")
    return result


def _count(value: object, path: str, maximum: int = MAX_COUNT) -> int:
    result = _typed(value, "count", path)
    if isinstance(result, bool) or not isinstance(result, int):
        raise SnapshotValidationError(f"{path}.data must be an integer")
    if not 0 <= result <= maximum:
        raise SnapshotValidationError(f"{path}.data must be between 0 and {maximum}")
    return result


def _string(value: object, path: str) -> str:
    result = _typed(value, "string", path)
    if not isinstance(result, str):
        raise SnapshotValidationError(f"{path}.data must be a string")
    return result


def _timestamp(value: object, path: str) -> datetime:
    result = _typed(value, "timestamp", path)
    if not isinstance(result, str):
        raise SnapshotValidationError(f"{path}.data must be an ISO-8601 string")

    normalized = result[:-1] + "+00:00" if result.endswith("Z") else result
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise SnapshotValidationError(f"{path}.data is not a valid timestamp") from exc

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _address(value: object, path: str) -> IPAddress:
    result = _typed(value, "address", path)
    if not isinstance(result, str):
        raise SnapshotValidationError(f"{path}.data must be an IP address string")
    try:
        return ipaddress.ip_address(result)
    except ValueError as exc:
        raise SnapshotValidationError(f"{path}.data is not a valid IP address") from exc


def _validate_metadata(value: object) -> None:
    entries = _vector(value, "event.metadata")
    if len(entries) != 1:
        raise SnapshotValidationError("event.metadata must contain network time only")
    pair = _vector(entries[0], "event.metadata[0]")
    if len(pair) != 2 or _count(pair[0], "event.metadata[0].key") != 1:
        raise SnapshotValidationError("event.metadata[0] must be network time metadata")
    _timestamp(pair[1], "event.metadata[0].value")


def _decode_event_envelope(
    raw: str | bytes, expected_topic: str
) -> tuple[str, list[Any]]:
    """Validate the common Broker envelope once and return name and arguments."""

    message = _json_object(raw, "WebSocket message")
    _exact_keys(message, {"type", "topic", "@data-type", "data"}, "message")
    if message["type"] != "data-message":
        raise SnapshotValidationError("message.type must be 'data-message'")
    if message["topic"] != expected_topic:
        raise SnapshotValidationError(f"unexpected topic {message['topic']!r}")

    outer = _vector({"@data-type": message["@data-type"], "data": message["data"]}, "message")
    if len(outer) != 3:
        raise SnapshotValidationError("message event envelope must contain three values")
    if _count(outer[0], "message.format") != 1:
        raise SnapshotValidationError("unsupported Zeek WebSocket format")
    if _count(outer[1], "message.message_type") != 1:
        raise SnapshotValidationError("message is not a Zeek event")

    event = _vector(outer[2], "event")
    if len(event) not in {2, 3}:
        raise SnapshotValidationError("event must contain name, arguments, and optional metadata")
    event_name = _string(event[0], "event.name")
    args = _vector(event[1], "event.args")
    if len(event) == 3:
        _validate_metadata(event[2])
    return event_name, args


def validate_ack(raw: str | bytes) -> dict[str, str]:
    message = _json_object(raw, "WebSocket acknowledgement")
    _exact_keys(message, {"type", "endpoint", "version"}, "acknowledgement")
    if message["type"] != "ack":
        raise SnapshotValidationError("WebSocket acknowledgement has the wrong type")
    if not isinstance(message["endpoint"], str) or not message["endpoint"]:
        raise SnapshotValidationError("WebSocket acknowledgement endpoint is invalid")
    if not isinstance(message["version"], str) or not message["version"]:
        raise SnapshotValidationError("WebSocket acknowledgement version is invalid")
    return message


def decode_flow_snapshot(raw: str | bytes, expected_topic: str = DEFAULT_TOPIC) -> FlowSnapshot:
    """Decode one Zeek WebSocket data message, rejecting schema deviations."""

    event_name, args = _decode_event_envelope(raw, expected_topic)
    if event_name != FLOW_SNAPSHOT_EVENT:
        raise SnapshotValidationError("unexpected Zeek event name")
    return _decode_flow_snapshot_args(args)


def _decode_flow_snapshot_args(args: list[Any]) -> FlowSnapshot:
    if len(args) != 20:
        raise SnapshotValidationError("flow_snapshot must contain exactly 20 arguments")

    schema_version = _count(args[0], "args[0]")
    if schema_version != SCHEMA_VERSION:
        raise SnapshotValidationError(f"unsupported snapshot schema {schema_version}")

    kind = _string(args[1], "args[1]")
    if kind not in VALID_KINDS:
        raise SnapshotValidationError(f"invalid snapshot kind {kind!r}")

    snapshot = FlowSnapshot(
        schema_version=schema_version,
        kind=kind,
        observed_at=_timestamp(args[2], "args[2]"),
        uid=_string(args[3], "args[3]"),
        orig_h=_address(args[4], "args[4]"),
        orig_p=_count(args[5], "args[5]", 65535),
        resp_h=_address(args[6], "args[6]"),
        resp_p=_count(args[7], "args[7]", 65535),
        ip_proto=_count(args[8], "args[8]", 65535),
        first_seen=_timestamp(args[9], "args[9]"),
        last_seen=_timestamp(args[10], "args[10]"),
        orig_pkts=_count(args[11], "args[11]"),
        orig_ip_bytes=_count(args[12], "args[12]"),
        orig_payload_bytes=_count(args[13], "args[13]"),
        resp_pkts=_count(args[14], "args[14]"),
        resp_ip_bytes=_count(args[15], "args[15]"),
        resp_payload_bytes=_count(args[16], "args[16]"),
        orig_state=_count(args[17], "args[17]"),
        resp_state=_count(args[18], "args[18]"),
        history=_string(args[19], "args[19]"),
    )

    if not snapshot.uid:
        raise SnapshotValidationError("snapshot UID must not be empty")
    if snapshot.last_seen < snapshot.first_seen:
        raise SnapshotValidationError("last_seen must not precede first_seen")
    if snapshot.observed_at < snapshot.last_seen:
        raise SnapshotValidationError("observed_at must not precede last_seen")
    return snapshot


def _decode_tcp_connection_signal(args: list[Any]) -> TcpConnectionSignal:
    if len(args) != 10:
        raise SnapshotValidationError(
            "tcp_connection_signal must contain exactly 10 arguments"
        )
    schema_version = _count(args[0], "args[0]")
    if schema_version != SCHEMA_VERSION:
        raise SnapshotValidationError(f"unsupported TCP signal schema {schema_version}")
    kind = _string(args[3], "args[3]")
    if kind not in VALID_TCP_SIGNAL_KINDS:
        raise SnapshotValidationError(f"invalid TCP signal kind {kind!r}")
    actor_role = _string(args[9], "args[9]")
    if actor_role not in VALID_ACTOR_ROLES:
        raise SnapshotValidationError(f"invalid TCP actor role {actor_role!r}")

    signal = TcpConnectionSignal(
        schema_version=schema_version,
        event_time=_timestamp(args[1], "args[1]"),
        zeek_uid=_string(args[2], "args[2]"),
        kind=kind,
        orig_h=_address(args[4], "args[4]"),
        orig_p=_count(args[5], "args[5]", 65535),
        resp_h=_address(args[6], "args[6]"),
        resp_p=_count(args[7], "args[7]", 65535),
        ip_protocol=_count(args[8], "args[8]", 65535),
        actor_role=actor_role,
    )
    if not signal.zeek_uid:
        raise SnapshotValidationError("TCP signal UID must not be empty")
    if signal.ip_protocol != 6:
        raise SnapshotValidationError("TCP signal ip_protocol must be 6")
    if signal.kind != "reset" and signal.actor_role != "unknown":
        raise SnapshotValidationError(
            "actor_role is only meaningful for reset and must otherwise be unknown"
        )
    return signal


def decode_stream_event(
    raw: str | bytes, expected_topic: str = DEFAULT_TOPIC
) -> StreamEvent:
    """Strictly dispatch one validated Zeek event by its event name."""

    event_name, args = _decode_event_envelope(raw, expected_topic)
    if event_name == FLOW_SNAPSHOT_EVENT:
        # Avoid reparsing the envelope while preserving the focused decoder's
        # public behavior through the shared field implementation below.
        return _decode_flow_snapshot_args(args)
    if event_name == TCP_SIGNAL_EVENT:
        return _decode_tcp_connection_signal(args)
    raise SnapshotValidationError(f"unsupported Zeek event name {event_name!r}")


def websocket_uri(host: str, port: int) -> str:
    if not host:
        raise ValueError("WebSocket host must not be empty")
    if not 1 <= port <= 65535:
        raise ValueError("WebSocket port must be between 1 and 65535")
    rendered_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return f"ws://{rendered_host}:{port}{WEBSOCKET_PATH}"


def _default_connector() -> tuple[Connector, tuple[type[BaseException], ...]]:
    try:
        from websockets.exceptions import WebSocketException
        from websockets.sync.client import connect
    except ImportError as exc:
        raise RuntimeError(
            "the 'websockets==17.1' dependency is required; install requirements.txt"
        ) from exc
    return connect, (OSError, TimeoutError, WebSocketException)


def iter_events(
    uri: str,
    topic: str = DEFAULT_TOPIC,
    *,
    reconnect_initial: float = 1.0,
    reconnect_max: float = 30.0,
    handshake_timeout: float = 10.0,
    connector: Connector | None = None,
    sleep: Callable[[float], None] = time.sleep,
    error_stream: TextIO = sys.stderr,
) -> Iterator[StreamEvent]:
    """Yield strictly validated known events and reconnect on network failures."""

    if not topic:
        raise ValueError("topic must not be empty")
    if reconnect_initial <= 0 or reconnect_max < reconnect_initial:
        raise ValueError("invalid reconnect delay configuration")

    if connector is None:
        connector, network_errors = _default_connector()
    else:
        network_errors = (OSError, TimeoutError, ConnectionError)
    recoverable_errors = network_errors + (SnapshotValidationError,)
    delay = reconnect_initial

    while True:
        try:
            with connector(uri, open_timeout=handshake_timeout, close_timeout=5.0) as websocket:
                websocket.send(json.dumps([topic], separators=(",", ":")))
                validate_ack(websocket.recv(timeout=handshake_timeout))
                delay = reconnect_initial

                while True:
                    raw = websocket.recv()
                    try:
                        yield decode_stream_event(raw, expected_topic=topic)
                    except SnapshotValidationError as exc:
                        print(f"Rejected Zeek WebSocket message: {exc}", file=error_stream)
        except recoverable_errors as exc:
            print(
                f"Zeek WebSocket unavailable ({exc}); retrying in {delay:g}s",
                file=error_stream,
            )
            sleep(delay)
            delay = min(delay * 2, reconnect_max)


def iter_snapshots(
    uri: str,
    topic: str = DEFAULT_TOPIC,
    *,
    reconnect_initial: float = 1.0,
    reconnect_max: float = 30.0,
    handshake_timeout: float = 10.0,
    connector: Connector | None = None,
    sleep: Callable[[float], None] = time.sleep,
    error_stream: TextIO = sys.stderr,
) -> Iterator[FlowSnapshot]:
    """Yield only snapshots while preserving the Phase 1 iterator API."""

    for event in iter_events(
        uri,
        topic,
        reconnect_initial=reconnect_initial,
        reconnect_max=reconnect_max,
        handshake_timeout=handshake_timeout,
        connector=connector,
        sleep=sleep,
        error_stream=error_stream,
    ):
        if isinstance(event, FlowSnapshot):
            yield event


def _port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=os.getenv("FLOW_STREAM_HOST", DEFAULT_HOST))
    parser.add_argument(
        "--port", type=_port, default=_port(os.getenv("FLOW_STREAM_PORT", str(DEFAULT_PORT)))
    )
    parser.add_argument("--topic", default=os.getenv("FLOW_STREAM_TOPIC", DEFAULT_TOPIC))
    args = parser.parse_args(argv)

    uri = websocket_uri(args.host, args.port)
    try:
        for event in iter_events(uri, args.topic):
            print(json.dumps(event.to_dict(), sort_keys=True), flush=True)
    except KeyboardInterrupt:
        return 130
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
