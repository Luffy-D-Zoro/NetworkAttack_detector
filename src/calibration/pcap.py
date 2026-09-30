"""Faithful offline PCAP replay through the production Zeek event producers."""

from __future__ import annotations

import ipaddress
import heapq
import json
import subprocess
import tempfile
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from src.ingestion.zeek_websocket import (
    DNSQueryObservation, DNSResultObservation, EncryptedProtocolObservation,
    FlowSnapshot, StreamEvent, TcpConnectionSignal,
)


class ZeekReplayError(RuntimeError):
    pass


def _timestamp(value: object) -> datetime:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return datetime.fromtimestamp(float(value), tz=UTC)
    if isinstance(value, str):
        normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
        parsed = datetime.fromisoformat(normalized)
        return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)
    raise ZeekReplayError(f"invalid Zeek log timestamp {value!r}")


def iter_zeek_pcap_events(
    pcap_path: Path,
    *,
    policy_path: Path,
    zeek_binary: str = "zeek",
    replay_speed: float = 1.0,
    snapshot_interval: str = "1sec",
    capture_policy: Path | None = None,
) -> Iterator[StreamEvent]:
    """Yield exact production events from an offline Zeek replay.

    The offline-only policy logs the same local event objects that the live
    policy publishes to WebSocket. This avoids conn.log approximation and
    avoids retaining events in memory inside Zeek. `replay_speed` remains an
    accepted compatibility option but offline extraction intentionally runs as
    fast as Zeek can process the capture.
    """

    if replay_speed <= 0:
        raise ValueError("replay_speed must be positive")
    if not pcap_path.is_file():
        raise FileNotFoundError(pcap_path)
    if not policy_path.is_file():
        raise FileNotFoundError(policy_path)
    capture_policy = capture_policy or (
        Path(__file__).resolve().parents[2] / "zeek" / "calibration_capture.zeek"
    )
    if not capture_policy.is_file():
        raise FileNotFoundError(capture_policy)

    with tempfile.TemporaryDirectory(prefix="sih-zeek-replay-") as output_dir:
        result = subprocess.run(
            [
                zeek_binary, "-C", "-r", str(pcap_path.resolve()),
                str(policy_path.resolve()), str(capture_policy.resolve()),
                "FlowStream::enable_websocket=F",
                "FlowStream::emit_local_events=T",
                f"FlowStream::snapshot_interval={snapshot_interval}",
            ],
            cwd=output_dir, capture_output=True, text=True, check=False,
        )
        if result.returncode:
            raise ZeekReplayError(
                f"Zeek exited with {result.returncode}: {result.stderr.strip()}"
            )
        if "error in" in result.stderr.lower():
            raise ZeekReplayError(f"Zeek policy error: {result.stderr.strip()}")
        root = Path(output_dir)
        streams = []
        for kind, name in (
            ("flow", "calibration_flow.log"),
            ("tcp", "calibration_tcp.log"),
            ("dns_query", "calibration_dns_query.log"),
            ("dns_result", "calibration_dns_result.log"),
            ("encrypted", "calibration_encrypted.log"),
        ):
            path = root / name
            if path.exists():
                streams.append(_read_log(path, kind))
        for _, event in heapq.merge(*streams, key=lambda item: item[0]):
            yield event


def _read_log(path: Path, kind: str) -> Iterator[tuple[int, StreamEvent]]:
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            raw = json.loads(line)
            yield int(raw.pop("seq")), _decode_log(kind, raw)


def _decode_log(kind: str, value: dict[str, object]) -> StreamEvent:
    ip = ipaddress.ip_address
    if kind == "flow":
        return FlowSnapshot(
            int(value["version"]), str(value["kind"]), _timestamp(value["observed_at"]),
            str(value["uid"]), ip(str(value["orig_h"])), int(value["orig_p"]),
            ip(str(value["resp_h"])), int(value["resp_p"]), int(value["ip_proto"]),
            _timestamp(value["first_seen"]), _timestamp(value["last_seen"]),
            int(value["orig_pkts"]), int(value["orig_ip_bytes"]), int(value["orig_payload_bytes"]),
            int(value["resp_pkts"]), int(value["resp_ip_bytes"]), int(value["resp_payload_bytes"]),
            int(value["orig_state"]), int(value["resp_state"]), str(value["history"]),
        )
    if kind == "tcp":
        return TcpConnectionSignal(
            int(value["version"]), _timestamp(value["event_time"]), str(value["uid"]),
            str(value["kind"]), ip(str(value["orig_h"])), int(value["orig_p"]),
            ip(str(value["resp_h"])), int(value["resp_p"]), int(value["ip_proto"]),
            str(value["actor_role"]),
        )
    if kind == "dns_query":
        return DNSQueryObservation(
            int(value["version"]), _timestamp(value["event_time"]), str(value["uid"]),
            ip(str(value["source_ip"])), int(value["source_port"]),
            ip(str(value["resolver_ip"])), int(value["resolver_port"]),
            int(value["ip_proto"]), int(value["transaction_id"]),
            str(value["query"]), int(value["qtype"]), int(value["qclass"]),
        )
    if kind == "dns_result":
        return DNSResultObservation(
            int(value["version"]), _timestamp(value["query_time"]),
            _timestamp(value["result_time"]), str(value["uid"]),
            ip(str(value["source_ip"])), ip(str(value["resolver_ip"])),
            int(value["ip_proto"]), int(value["transaction_id"]),
            str(value["query"]) if "query" in value else None,
            bool(value["saw_reply"]), bool(value["rejected"]),
            int(value["rcode"]) if "rcode" in value else None,
            float(value["rtt"]) if "rtt" in value else None,
            int(value["answer_count"]) if "answer_count" in value else None,
        )
    if kind == "encrypted":
        return EncryptedProtocolObservation(
            int(value["version"]), str(value["kind"]), _timestamp(value["event_time"]),
            str(value["uid"]), str(value["family"]), ip(str(value["client_ip"])),
            int(value["client_port"]), ip(str(value["server_ip"])),
            int(value["server_port"]), int(value["ip_proto"]),
            _optional_str(value, "version_value"), _optional_str(value, "cipher"),
            _optional_str(value, "curve"), _optional_str(value, "server_name"),
            _optional_str(value, "alpn"), _optional_bool(value, "resumed"),
            _optional_bool(value, "established"), _optional_str(value, "last_alert"),
            _optional_str(value, "server_cert_fingerprint"),
            _optional_str(value, "client_fingerprint"),
        )
    raise ZeekReplayError(f"unknown calibration log kind {kind!r}")


def _optional_str(value: dict[str, object], name: str) -> str | None:
    return str(value[name]) if name in value else None


def _optional_bool(value: dict[str, object], name: str) -> bool | None:
    return bool(value[name]) if name in value else None
