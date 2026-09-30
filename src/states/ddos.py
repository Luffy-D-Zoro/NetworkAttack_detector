"""Bounded destination-centric aggregate state for future DDoS features."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timedelta

from src.flow.models import DirectionalConnectionEvent, DirectionalFlowUpdate
from src.ingestion.zeek_websocket import TcpConnectionSignal
from src.states.common import BoundedCounterMap, BucketRing, CappedStateTable

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


@dataclass(frozen=True, slots=True)
class SourceCounters:
    packets: int = 0
    ip_bytes: int = 0
    connection_starts: int = 0

    def __add__(self, other: SourceCounters) -> SourceCounters:
        return SourceCounters(
            self.packets + other.packets,
            self.ip_bytes + other.ip_bytes,
            self.connection_starts + other.connection_starts,
        )


@dataclass(slots=True)
class DDoSBucket:
    bucket_start: datetime
    packets: int
    ip_bytes: int
    connection_starts: int
    protocol_packets: BoundedCounterMap[int, int]
    protocol_bytes: BoundedCounterMap[int, int]
    destination_ports: BoundedCounterMap[int, int]
    observed_sources: BoundedCounterMap[IPAddress, SourceCounters]
    syn_starts: int
    tcp_established: int
    tcp_attempt_timeouts: int
    tcp_rejected: int
    tcp_resets_from_source: int
    tcp_resets_from_destination: int
    tcp_resets_unknown: int

    @property
    def source_overflow_packets(self) -> int:
        return self.observed_sources.overflow_value.packets

    @property
    def source_overflow_bytes(self) -> int:
        return self.observed_sources.overflow_value.ip_bytes

    @property
    def source_overflow_starts(self) -> int:
        return self.observed_sources.overflow_value.connection_starts


@dataclass(slots=True)
class DDoSState:
    last_activity: datetime
    buckets: BucketRing[DDoSBucket]


@dataclass(frozen=True, slots=True)
class DDoSStateConfig:
    window: timedelta = timedelta(seconds=60)
    bucket_width: timedelta = timedelta(seconds=5)
    inactivity_timeout: timedelta = timedelta(seconds=120)
    cleanup_interval: timedelta = timedelta(seconds=5)
    max_state_entries: int = 10_000
    source_capacity: int = 4_096
    port_capacity: int = 1_024
    protocol_capacity: int = 32


class DDoSStateManager:
    """Maintain exact bounded aggregates keyed by observed destination IP."""

    def __init__(self, config: DDoSStateConfig | None = None) -> None:
        self.config = config or DDoSStateConfig()
        self._validate_config()
        self._states: CappedStateTable[IPAddress, DDoSState] = CappedStateTable(
            capacity=self.config.max_state_entries
        )
        self._watermark: datetime | None = None
        self._last_cleanup_at: datetime | None = None

    def __len__(self) -> int:
        return len(self._states)

    @property
    def capacity_evictions(self) -> int:
        return self._states.capacity_evictions

    def get(self, dst_ip: IPAddress) -> DDoSState | None:
        return self._states.get(dst_ip)

    def update_flow(self, update: DirectionalFlowUpdate) -> bool:
        bucket = self._bucket(update.key.dst_ip, update.last_seen)
        if bucket is None:
            return False
        bucket.packets += update.packet_delta
        bucket.ip_bytes += update.byte_delta
        bucket.protocol_packets.add(update.key.protocol, update.packet_delta)
        bucket.protocol_bytes.add(update.key.protocol, update.byte_delta)
        bucket.observed_sources.add(
            update.key.src_ip,
            SourceCounters(update.packet_delta, update.byte_delta, 0),
        )
        return True

    def update_connection(self, event: DirectionalConnectionEvent) -> bool:
        if event.kind != "start" or event.direction_role != "originator":
            return False
        bucket = self._bucket(event.key.dst_ip, event.event_time)
        if bucket is None:
            return False
        bucket.connection_starts += 1
        bucket.destination_ports.add(event.key.dst_port, 1)
        bucket.observed_sources.add(event.key.src_ip, SourceCounters(0, 0, 1))
        return True

    def update_tcp(self, signal: TcpConnectionSignal) -> bool:
        bucket = self._bucket(signal.resp_h, signal.event_time)
        if bucket is None:
            return False
        if signal.kind == "syn_start":
            bucket.syn_starts += 1
        elif signal.kind == "established":
            bucket.tcp_established += 1
        elif signal.kind == "attempt_timeout":
            bucket.tcp_attempt_timeouts += 1
        elif signal.kind == "rejected":
            bucket.tcp_rejected += 1
        elif signal.actor_role == "orig":
            bucket.tcp_resets_from_source += 1
        elif signal.actor_role == "resp":
            bucket.tcp_resets_from_destination += 1
        else:
            bucket.tcp_resets_unknown += 1
        return True

    def maybe_expire(self, now: datetime) -> int | None:
        if self._last_cleanup_at is None:
            self._last_cleanup_at = now
            return None
        if now < self._last_cleanup_at:
            return None
        if now - self._last_cleanup_at < self.config.cleanup_interval:
            return None
        self._last_cleanup_at = now
        return self.expire(now)

    def expire(self, now: datetime) -> int:
        if self._watermark is None or now > self._watermark:
            self._watermark = now
        expired: list[IPAddress] = []
        for key, state in self._states.items():
            state.buckets.expire(now)
            if (
                len(state.buckets) == 0
                and state.last_activity <= now - self.config.inactivity_timeout
            ):
                expired.append(key)
        for key in expired:
            self._states.remove(key)
        return len(expired)

    def _bucket(self, dst_ip: IPAddress, event_time: datetime) -> DDoSBucket | None:
        if not self._accept_event_time(event_time):
            return None
        state = self._states.get(dst_ip)
        if state is None:
            state = self._states.get_or_create(
                dst_ip,
                lambda: DDoSState(event_time, self._new_ring()),
            )
        bucket = state.buckets.bucket_for(event_time)
        if bucket is None:
            return None
        state.last_activity = max(state.last_activity, event_time)
        self._states.touch(dst_ip)
        return bucket

    def _accept_event_time(self, event_time: datetime) -> bool:
        if (
            self._watermark is not None
            and event_time < self._watermark - self.config.window
        ):
            return False
        if self._watermark is None or event_time > self._watermark:
            self._watermark = event_time
        return True

    def _new_ring(self) -> BucketRing[DDoSBucket]:
        return BucketRing(
            window=self.config.window,
            bucket_width=self.config.bucket_width,
            factory=self._new_bucket,
        )

    def _new_bucket(self, start: datetime) -> DDoSBucket:
        return DDoSBucket(
            bucket_start=start,
            packets=0,
            ip_bytes=0,
            connection_starts=0,
            protocol_packets=BoundedCounterMap(
                capacity=self.config.protocol_capacity, zero=0
            ),
            protocol_bytes=BoundedCounterMap(
                capacity=self.config.protocol_capacity, zero=0
            ),
            destination_ports=BoundedCounterMap(
                capacity=self.config.port_capacity, zero=0
            ),
            observed_sources=BoundedCounterMap(
                capacity=self.config.source_capacity, zero=SourceCounters()
            ),
            syn_starts=0,
            tcp_established=0,
            tcp_attempt_timeouts=0,
            tcp_rejected=0,
            tcp_resets_from_source=0,
            tcp_resets_from_destination=0,
            tcp_resets_unknown=0,
        )

    def _validate_config(self) -> None:
        durations = (
            self.config.window,
            self.config.bucket_width,
            self.config.inactivity_timeout,
            self.config.cleanup_interval,
        )
        capacities = (
            self.config.max_state_entries,
            self.config.source_capacity,
            self.config.port_capacity,
            self.config.protocol_capacity,
        )
        if any(value <= timedelta(0) for value in durations):
            raise ValueError("DDoS durations must be positive")
        if any(value <= 0 for value in capacities):
            raise ValueError("DDoS capacities must be positive")
