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
DNS_QUERY_EVENT = "FlowStream::dns_query_observation"
DNS_RESULT_EVENT = "FlowStream::dns_result_observation"
ENCRYPTED_PROTOCOL_EVENT = "FlowStream::encrypted_protocol_observation"
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
VALID_ENCRYPTED_KINDS = frozenset({"identified", "metadata"})
VALID_SECURITY_FAMILIES = frozenset({"tls", "dtls", "quic"})
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


@dataclass(frozen=True, slots=True)
class DNSQueryObservation:
    """One DNS query delivered immediately by Zeek."""

    schema_version: int
    event_time: datetime
    zeek_uid: str
    source_ip: IPAddress
    source_port: int
    resolver_ip: IPAddress
    resolver_port: int
    ip_protocol: int
    transaction_id: int
    query: str
    qtype: int
    qclass: int

    def to_dict(self) -> dict[str, object]:
        result = asdict(self)
        result["event_time"] = _format_timestamp(self.event_time)
        result["source_ip"] = str(self.source_ip)
        result["resolver_ip"] = str(self.resolver_ip)
        return result


@dataclass(frozen=True, slots=True)
class DNSResultObservation:
    """One finalized DNS transaction outcome delivered by Zeek."""

    schema_version: int
    query_time: datetime
    result_time: datetime
    zeek_uid: str
    source_ip: IPAddress
    resolver_ip: IPAddress
    ip_protocol: int
    transaction_id: int
    query: str | None
    saw_reply: bool
    rejected: bool
    rcode: int | None
    rtt: float | None
    answer_count: int | None

    def to_dict(self) -> dict[str, object]:
        result = asdict(self)
        result["query_time"] = _format_timestamp(self.query_time)
        result["result_time"] = _format_timestamp(self.result_time)
        result["source_ip"] = str(self.source_ip)
        result["resolver_ip"] = str(self.resolver_ip)
        return result


@dataclass(frozen=True, slots=True)
class EncryptedProtocolObservation:
    """TLS, DTLS, or QUIC identification/metadata without payload data."""

    schema_version: int
    kind: str
    event_time: datetime
    zeek_uid: str
    security_family: str
    client_ip: IPAddress
    client_port: int
    server_ip: IPAddress
    server_port: int
    ip_protocol: int
    version: str | None
    cipher: str | None
    curve: str | None
    server_name: str | None
    alpn: str | None
    resumed: bool | None
    established: bool | None
    last_alert: str | None
    server_cert_fingerprint: str | None
    client_fingerprint: str | None

    def to_dict(self) -> dict[str, object]:
        result = asdict(self)
        result["event_time"] = _format_timestamp(self.event_time)
        result["client_ip"] = str(self.client_ip)
        result["server_ip"] = str(self.server_ip)
        return result


StreamEvent = (
    FlowSnapshot
    | TcpConnectionSignal
    | DNSQueryObservation
    | DNSResultObservation
    | EncryptedProtocolObservation
)


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


def _boolean(value: object, path: str) -> bool:
    result = _typed(value, "boolean", path)
    if not isinstance(result, bool):
        raise SnapshotValidationError(f"{path}.data must be a boolean")
    return result


def _real(value: object, path: str) -> float:
    result = _typed(value, "real", path)
    if isinstance(result, bool) or not isinstance(result, (int, float)):
        raise SnapshotValidationError(f"{path}.data must be a finite number")
    result = float(result)
    if not (-float("inf") < result < float("inf")):
        raise SnapshotValidationError(f"{path}.data must be a finite number")
    return result


def _optional_string(args: list[Any], index: int, name: str) -> str | None:
    present = _boolean(args[index], f"args[{index}] ({name}.present)")
    value = _string(args[index + 1], f"args[{index + 1}] ({name}.value)")
    if not present:
        return None
    if not value:
        raise SnapshotValidationError(f"present optional {name} must not be empty")
    return value


def _optional_count(args: list[Any], index: int, name: str) -> int | None:
    present = _boolean(args[index], f"args[{index}] ({name}.present)")
    value = _count(args[index + 1], f"args[{index + 1}] ({name}.value)")
    return value if present else None


def _optional_real(args: list[Any], index: int, name: str) -> float | None:
    present = _boolean(args[index], f"args[{index}] ({name}.present)")
    value = _real(args[index + 1], f"args[{index + 1}] ({name}.value)")
    return value if present else None


def _optional_boolean(args: list[Any], index: int, name: str) -> bool | None:
    present = _boolean(args[index], f"args[{index}] ({name}.present)")
    value = _boolean(args[index + 1], f"args[{index + 1}] ({name}.value)")
    return value if present else None


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


def _schema(args: list[Any], label: str) -> int:
    schema_version = _count(args[0], "args[0]")
    if schema_version != SCHEMA_VERSION:
        raise SnapshotValidationError(f"unsupported {label} schema {schema_version}")
    return schema_version


def _decode_dns_query(args: list[Any]) -> DNSQueryObservation:
    if len(args) != 12:
        raise SnapshotValidationError("dns_query_observation must contain exactly 12 arguments")
    observation = DNSQueryObservation(
        schema_version=_schema(args, "DNS query"),
        event_time=_timestamp(args[1], "args[1]"),
        zeek_uid=_string(args[2], "args[2]"),
        source_ip=_address(args[3], "args[3]"),
        source_port=_count(args[4], "args[4]", 65535),
        resolver_ip=_address(args[5], "args[5]"),
        resolver_port=_count(args[6], "args[6]", 65535),
        ip_protocol=_count(args[7], "args[7]", 65535),
        transaction_id=_count(args[8], "args[8]", 65535),
        query=_string(args[9], "args[9]"),
        qtype=_count(args[10], "args[10]", 65535),
        qclass=_count(args[11], "args[11]", 65535),
    )
    if not observation.zeek_uid:
        raise SnapshotValidationError("DNS query UID must not be empty")
    if observation.ip_protocol not in {6, 17}:
        raise SnapshotValidationError("DNS query ip_protocol must be TCP or UDP")
    return observation


def _decode_dns_result(args: list[Any]) -> DNSResultObservation:
    if len(args) != 18:
        raise SnapshotValidationError("dns_result_observation must contain exactly 18 arguments")
    observation = DNSResultObservation(
        schema_version=_schema(args, "DNS result"),
        query_time=_timestamp(args[1], "args[1]"),
        result_time=_timestamp(args[2], "args[2]"),
        zeek_uid=_string(args[3], "args[3]"),
        source_ip=_address(args[4], "args[4]"),
        resolver_ip=_address(args[5], "args[5]"),
        ip_protocol=_count(args[6], "args[6]", 65535),
        transaction_id=_count(args[7], "args[7]", 65535),
        query=_optional_string(args, 8, "query"),
        saw_reply=_boolean(args[10], "args[10]"),
        rejected=_boolean(args[11], "args[11]"),
        rcode=_optional_count(args, 12, "rcode"),
        rtt=_optional_real(args, 14, "rtt"),
        answer_count=_optional_count(args, 16, "answer_count"),
    )
    if not observation.zeek_uid:
        raise SnapshotValidationError("DNS result UID must not be empty")
    if observation.ip_protocol not in {6, 17}:
        raise SnapshotValidationError("DNS result ip_protocol must be TCP or UDP")
    if observation.result_time < observation.query_time:
        raise SnapshotValidationError("DNS result_time must not precede query_time")
    if observation.rtt is not None and observation.rtt < 0:
        raise SnapshotValidationError("DNS RTT must not be negative")
    return observation


def _decode_encrypted_protocol(args: list[Any]) -> EncryptedProtocolObservation:
    if len(args) != 30:
        raise SnapshotValidationError(
            "encrypted_protocol_observation must contain exactly 30 arguments"
        )
    kind = _string(args[1], "args[1]")
    family = _string(args[4], "args[4]")
    if kind not in VALID_ENCRYPTED_KINDS:
        raise SnapshotValidationError(f"invalid encrypted observation kind {kind!r}")
    if family not in VALID_SECURITY_FAMILIES:
        raise SnapshotValidationError(f"invalid security family {family!r}")
    observation = EncryptedProtocolObservation(
        schema_version=_schema(args, "encrypted protocol"),
        kind=kind,
        event_time=_timestamp(args[2], "args[2]"),
        zeek_uid=_string(args[3], "args[3]"),
        security_family=family,
        client_ip=_address(args[5], "args[5]"),
        client_port=_count(args[6], "args[6]", 65535),
        server_ip=_address(args[7], "args[7]"),
        server_port=_count(args[8], "args[8]", 65535),
        ip_protocol=_count(args[9], "args[9]", 65535),
        version=_optional_string(args, 10, "version"),
        cipher=_optional_string(args, 12, "cipher"),
        curve=_optional_string(args, 14, "curve"),
        server_name=_optional_string(args, 16, "server_name"),
        alpn=_optional_string(args, 18, "alpn"),
        resumed=_optional_boolean(args, 20, "resumed"),
        established=_optional_boolean(args, 22, "established"),
        last_alert=_optional_string(args, 24, "last_alert"),
        server_cert_fingerprint=_optional_string(args, 26, "server_cert_fingerprint"),
        client_fingerprint=_optional_string(args, 28, "client_fingerprint"),
    )
    if not observation.zeek_uid:
        raise SnapshotValidationError("encrypted observation UID must not be empty")
    expected_protocol = 17 if family in {"dtls", "quic"} else 6
    if observation.ip_protocol != expected_protocol:
        raise SnapshotValidationError(
            f"{family} observation must use IP protocol {expected_protocol}"
        )
    return observation


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
    if event_name == DNS_QUERY_EVENT:
        return _decode_dns_query(args)
    if event_name == DNS_RESULT_EVENT:
        return _decode_dns_result(args)
    if event_name == ENCRYPTED_PROTOCOL_EVENT:
        return _decode_encrypted_protocol(args)
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
            "the 'websockets==16.1.1' dependency is required; install requirements.txt"
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
