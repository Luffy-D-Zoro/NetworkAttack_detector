"""Bounded source-centric aggregate state for future scan features."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timedelta

from src.flow.models import DirectionalConnectionEvent
from src.ingestion.zeek_websocket import TcpConnectionSignal
from src.states.common import (
    BoundedCounterMap,
    BoundedHashSet,
    BucketRing,
    CappedStateTable,
)

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


@dataclass(slots=True)
class ScanBucket:
    bucket_start: datetime
    connection_starts: int
    protocol_starts: BoundedCounterMap[int, int]
    destination_ips: BoundedCounterMap[IPAddress, int]
    destination_ports: BoundedCounterMap[tuple[int, int], int]
    destination_pairs: BoundedHashSet
    syn_starts: int
    tcp_established: int
    tcp_attempt_timeouts: int
    tcp_rejected: int
    tcp_resets: int

    @property
    def destination_pair_overflow(self) -> int:
        return self.destination_pairs.overflow_count


@dataclass(slots=True)
class ScanState:
    last_activity: datetime
    buckets: BucketRing[ScanBucket]


@dataclass(frozen=True, slots=True)
class ScanStateConfig:
    window: timedelta = timedelta(seconds=300)
    bucket_width: timedelta = timedelta(seconds=10)
    inactivity_timeout: timedelta = timedelta(seconds=600)
    cleanup_interval: timedelta = timedelta(seconds=5)
    max_state_entries: int = 10_000
    destination_ip_capacity: int = 4_096
    destination_port_capacity: int = 4_096
    destination_pair_capacity: int = 8_192
    protocol_capacity: int = 32


class ScanStateManager:
    """Maintain exact bounded aggregates keyed by observed source IP."""

    def __init__(self, config: ScanStateConfig | None = None) -> None:
        self.config = config or ScanStateConfig()
        self._validate_config()
        self._states: CappedStateTable[IPAddress, ScanState] = CappedStateTable(
            capacity=self.config.max_state_entries
        )
        self._watermark: datetime | None = None
        self._last_cleanup_at: datetime | None = None

    def __len__(self) -> int:
        return len(self._states)

    @property
    def capacity_evictions(self) -> int:
        return self._states.capacity_evictions

    def get(self, src_ip: IPAddress) -> ScanState | None:
        return self._states.get(src_ip)

    def items(self) -> tuple[tuple[IPAddress, ScanState], ...]:
        """Return a stable read-only snapshot for periodic feature extraction."""

        return self._states.items()

    def update_connection(self, event: DirectionalConnectionEvent) -> bool:
        if event.kind != "start" or event.direction_role != "originator":
            return False
        bucket = self._bucket(event.key.src_ip, event.event_time)
        if bucket is None:
            return False
        bucket.connection_starts += 1
        bucket.protocol_starts.add(event.key.protocol, 1)
        bucket.destination_ips.add(event.key.dst_ip, 1)
        bucket.destination_ports.add((event.key.protocol, event.key.dst_port), 1)
        bucket.destination_pairs.add(
            (str(event.key.dst_ip), event.key.protocol, event.key.dst_port)
        )
        return True

    def update_tcp(self, signal: TcpConnectionSignal) -> bool:
        bucket = self._bucket(signal.orig_h, signal.event_time)
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
        else:
            bucket.tcp_resets += 1
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

    def _bucket(self, src_ip: IPAddress, event_time: datetime) -> ScanBucket | None:
        if not self._accept_event_time(event_time):
            return None
        state = self._states.get(src_ip)
        if state is None:
            state = self._states.get_or_create(
                src_ip,
                lambda: ScanState(event_time, self._new_ring()),
            )
        bucket = state.buckets.bucket_for(event_time)
        if bucket is None:
            return None
        state.last_activity = max(state.last_activity, event_time)
        self._states.touch(src_ip)
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

    def _new_ring(self) -> BucketRing[ScanBucket]:
        return BucketRing(
            window=self.config.window,
            bucket_width=self.config.bucket_width,
            factory=self._new_bucket,
        )

    def _new_bucket(self, start: datetime) -> ScanBucket:
        return ScanBucket(
            bucket_start=start,
            connection_starts=0,
            protocol_starts=BoundedCounterMap(
                capacity=self.config.protocol_capacity, zero=0
            ),
            destination_ips=BoundedCounterMap(
                capacity=self.config.destination_ip_capacity, zero=0
            ),
            destination_ports=BoundedCounterMap(
                capacity=self.config.destination_port_capacity, zero=0
            ),
            destination_pairs=BoundedHashSet(
                capacity=self.config.destination_pair_capacity
            ),
            syn_starts=0,
            tcp_established=0,
            tcp_attempt_timeouts=0,
            tcp_rejected=0,
            tcp_resets=0,
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
            self.config.destination_ip_capacity,
            self.config.destination_port_capacity,
            self.config.destination_pair_capacity,
            self.config.protocol_capacity,
        )
        if any(value <= timedelta(0) for value in durations):
            raise ValueError("scan durations must be positive")
        if any(value <= 0 for value in capacities):
            raise ValueError("scan capacities must be positive")
