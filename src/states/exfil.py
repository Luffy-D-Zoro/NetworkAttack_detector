"""Bounded directional source/destination state for future exfil features."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timedelta

from src.flow.models import DirectionalFlowUpdate
from src.states.common import BoundedCounterMap, BucketRing, CappedStateTable

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
ExfilKey = tuple[IPAddress, IPAddress]


@dataclass(slots=True)
class ExfilBucket:
    bucket_start: datetime
    packets: int
    ip_bytes: int
    protocol_packets: BoundedCounterMap[int, int]
    protocol_bytes: BoundedCounterMap[int, int]


@dataclass(slots=True)
class ExfilState:
    first_activity: datetime
    last_activity: datetime
    buckets: BucketRing[ExfilBucket]


@dataclass(frozen=True, slots=True)
class ExfilStateConfig:
    window: timedelta = timedelta(hours=1)
    bucket_width: timedelta = timedelta(minutes=1)
    inactivity_timeout: timedelta = timedelta(hours=2)
    cleanup_interval: timedelta = timedelta(seconds=30)
    max_state_entries: int = 50_000
    protocol_capacity: int = 32


class ExfilStateManager:
    """Aggregate directional deltas by `(src_ip, dst_ip)` without merging."""

    def __init__(self, config: ExfilStateConfig | None = None) -> None:
        self.config = config or ExfilStateConfig()
        self._validate_config()
        self._states: CappedStateTable[ExfilKey, ExfilState] = CappedStateTable(
            capacity=self.config.max_state_entries
        )
        self._watermark: datetime | None = None
        self._last_cleanup_at: datetime | None = None

    def __len__(self) -> int:
        return len(self._states)

    @property
    def capacity_evictions(self) -> int:
        return self._states.capacity_evictions

    def get(self, key: ExfilKey) -> ExfilState | None:
        return self._states.get(key)

    def items(self) -> tuple[tuple[ExfilKey, ExfilState], ...]:
        """Return a stable read-only snapshot for periodic feature extraction."""

        return self._states.items()

    def get_reverse(self, key: ExfilKey) -> ExfilState | None:
        """Optional O(1) reverse-state lookup without combining directions."""

        return self._states.get((key[1], key[0]))

    def update_flow(self, update: DirectionalFlowUpdate) -> bool:
        event_time = update.last_seen
        if not self._accept_event_time(event_time):
            return False
        state_key = (update.key.src_ip, update.key.dst_ip)
        state = self._states.get(state_key)
        if state is None:
            state = self._states.get_or_create(
                state_key,
                lambda: ExfilState(event_time, event_time, self._new_ring()),
            )
        bucket = state.buckets.bucket_for(event_time)
        if bucket is None:
            return False

        bucket.packets += update.packet_delta
        bucket.ip_bytes += update.byte_delta
        bucket.protocol_packets.add(update.key.protocol, update.packet_delta)
        bucket.protocol_bytes.add(update.key.protocol, update.byte_delta)
        state.first_activity = min(state.first_activity, event_time)
        state.last_activity = max(state.last_activity, event_time)
        self._states.touch(state_key)
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
        expired: list[ExfilKey] = []
        for state_key, state in self._states.items():
            state.buckets.expire(now)
            if (
                len(state.buckets) == 0
                and state.last_activity <= now - self.config.inactivity_timeout
            ):
                expired.append(state_key)
        for state_key in expired:
            self._states.remove(state_key)
        return len(expired)

    def _accept_event_time(self, event_time: datetime) -> bool:
        if (
            self._watermark is not None
            and event_time < self._watermark - self.config.window
        ):
            return False
        if self._watermark is None or event_time > self._watermark:
            self._watermark = event_time
        return True

    def _new_ring(self) -> BucketRing[ExfilBucket]:
        return BucketRing(
            window=self.config.window,
            bucket_width=self.config.bucket_width,
            factory=self._new_bucket,
        )

    def _new_bucket(self, start: datetime) -> ExfilBucket:
        return ExfilBucket(
            bucket_start=start,
            packets=0,
            ip_bytes=0,
            protocol_packets=BoundedCounterMap(
                capacity=self.config.protocol_capacity, zero=0
            ),
            protocol_bytes=BoundedCounterMap(
                capacity=self.config.protocol_capacity, zero=0
            ),
        )

    def _validate_config(self) -> None:
        durations = (
            self.config.window,
            self.config.bucket_width,
            self.config.inactivity_timeout,
            self.config.cleanup_interval,
        )
        capacities = (self.config.max_state_entries, self.config.protocol_capacity)
        if any(value <= timedelta(0) for value in durations):
            raise ValueError("exfil durations must be positive")
        if any(value <= 0 for value in capacities):
            raise ValueError("exfil capacities must be positive")
