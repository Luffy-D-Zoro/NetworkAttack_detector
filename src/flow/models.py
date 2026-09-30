"""Compact directional flow and connection lifecycle models."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import UTC, datetime

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class FlowKey:
    """A directional network five-tuple."""

    src_ip: IPAddress
    src_port: int
    dst_ip: IPAddress
    dst_port: int
    protocol: int

    def to_dict(self) -> dict[str, object]:
        return {
            "src_ip": str(self.src_ip),
            "src_port": self.src_port,
            "dst_ip": str(self.dst_ip),
            "dst_port": self.dst_port,
            "protocol": self.protocol,
        }


@dataclass(frozen=True, slots=True)
class DirectionalFlowUpdate:
    """New traffic in one direction derived from cumulative Zeek counters."""

    key: FlowKey
    first_seen: datetime
    last_seen: datetime
    packet_delta: int
    byte_delta: int
    zeek_uid: str

    def __post_init__(self) -> None:
        if self.packet_delta < 0 or self.byte_delta < 0:
            raise ValueError("directional deltas must not be negative")
        if self.packet_delta == 0 and self.byte_delta == 0:
            raise ValueError("a directional update must contain new traffic")
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen must not precede first_seen")
        if not self.zeek_uid:
            raise ValueError("zeek_uid must not be empty")


@dataclass(frozen=True, slots=True)
class DirectionalConnectionEvent:
    """One UID-deduplicated directional connection lifecycle observation."""

    schema_version: int
    kind: str
    event_time: datetime
    zeek_uid: str
    key: FlowKey
    direction_role: str
    first_seen: datetime
    last_seen: datetime
    total_packets: int
    total_ip_bytes: int

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError("unsupported directional connection event schema")
        if self.kind not in {"start", "final"}:
            raise ValueError("directional connection event kind must be start or final")
        if self.direction_role not in {"originator", "responder"}:
            raise ValueError("direction role must be originator or responder")
        if not self.zeek_uid:
            raise ValueError("zeek_uid must not be empty")
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen must not precede first_seen")
        if self.event_time < self.last_seen:
            raise ValueError("event_time must not precede last_seen")
        if self.total_packets < 0 or self.total_ip_bytes < 0:
            raise ValueError("connection totals must not be negative")
        if self.total_packets == 0 and self.total_ip_bytes == 0:
            raise ValueError("a lifecycle event must represent observed traffic")


@dataclass(slots=True)
class FlowState:
    """Compact aggregate state for one directional flow."""

    key: FlowKey
    first_seen: datetime
    last_seen: datetime
    packet_count: int = 0
    byte_count: int = 0

    @classmethod
    def from_update(cls, update: DirectionalFlowUpdate) -> FlowState:
        return cls(
            key=update.key,
            first_seen=update.first_seen,
            last_seen=update.last_seen,
            packet_count=update.packet_delta,
            byte_count=update.byte_delta,
        )

    def apply(self, update: DirectionalFlowUpdate) -> None:
        if update.key != self.key:
            raise ValueError("cannot apply an update for a different FlowKey")
        self.first_seen = min(self.first_seen, update.first_seen)
        self.last_seen = max(self.last_seen, update.last_seen)
        self.packet_count += update.packet_delta
        self.byte_count += update.byte_delta

    def to_dict(self) -> dict[str, object]:
        return {
            **self.key.to_dict(),
            "first_seen": _timestamp(self.first_seen),
            "last_seen": _timestamp(self.last_seen),
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
        }
