"""Bounded TLS, DTLS, and QUIC metadata/session state."""

from __future__ import annotations

import ipaddress
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timedelta

from src.flow.models import DirectionalFlowUpdate
from src.ingestion.zeek_websocket import EncryptedProtocolObservation, FlowSnapshot
from src.states.common import (
    BoundedCounterMap,
    BoundedEventDeduplicator,
    BoundedTimeDeque,
    BucketRing,
    CappedStateTable,
    stable_digest,
)

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
EncryptedKey = tuple[IPAddress, IPAddress, int, int, str]

_FIELD_BITS = {
    "version": 1 << 0,
    "cipher": 1 << 1,
    "curve": 1 << 2,
    "server_name": 1 << 3,
    "alpn": 1 << 4,
    "resumed": 1 << 5,
    "established": 1 << 6,
    "last_alert": 1 << 7,
    "server_cert_fingerprint": 1 << 8,
    "client_fingerprint": 1 << 9,
    "metadata_record": 1 << 10,
}


@dataclass(slots=True)
class EncryptedBucket:
    bucket_start: datetime
    session_starts: int
    metadata_records: int
    client_to_server_packets: int
    client_to_server_ip_bytes: int
    server_to_client_packets: int
    server_to_client_ip_bytes: int
    established_count: int
    failed_or_incomplete_count: int
    resumed_count: int
    alert_count: int
    version_counts: BoundedCounterMap[str, int]
    cipher_counts: BoundedCounterMap[str, int]
    curve_counts: BoundedCounterMap[str, int]
    alpn_counts: BoundedCounterMap[str, int]
    server_name_hashes: BoundedCounterMap[bytes, int]
    server_cert_fingerprints: BoundedCounterMap[str, int]
    client_fingerprints: BoundedCounterMap[str, int]


@dataclass(slots=True)
class EncryptedSessionAccumulator:
    zeek_uid: str
    first_seen: datetime
    last_seen: datetime
    client_to_server_packets: int
    client_to_server_ip_bytes: int
    server_to_client_packets: int
    server_to_client_ip_bytes: int
    metadata_seen: int
    directions_observed_mask: int = 0


@dataclass(frozen=True, slots=True)
class EncryptedSessionSample:
    end_time: datetime
    duration: float
    client_to_server_packets: int
    client_to_server_ip_bytes: int
    server_to_client_packets: int
    server_to_client_ip_bytes: int
    directions_observed_mask: int


@dataclass(slots=True)
class EncryptedState:
    last_activity: datetime
    buckets: BucketRing[EncryptedBucket]
    active_sessions: OrderedDict[str, EncryptedSessionAccumulator]
    completed_sessions: BoundedTimeDeque[EncryptedSessionSample]


@dataclass(frozen=True, slots=True)
class EncryptedStateConfig:
    window: timedelta = timedelta(minutes=30)
    bucket_width: timedelta = timedelta(seconds=30)
    completed_horizon: timedelta = timedelta(hours=2)
    completed_sample_capacity: int = 2_048
    session_timeout: timedelta = timedelta(minutes=10)
    inactivity_timeout: timedelta = timedelta(hours=1)
    cleanup_interval: timedelta = timedelta(seconds=30)
    max_state_entries: int = 50_000
    sessions_per_state: int = 4_096
    uid_capacity: int = 200_000
    category_capacity: int = 256
    final_dedup_horizon: timedelta = timedelta(minutes=10)
    final_dedup_capacity: int = 200_000
    category_length_limit: int = 256


class EncryptedStateManager:
    """Join protocol identity, directional deltas, and final snapshots by UID."""

    def __init__(self, config: EncryptedStateConfig | None = None) -> None:
        self.config = config or EncryptedStateConfig()
        self._validate_config()
        self._states: CappedStateTable[EncryptedKey, EncryptedState] = CappedStateTable(
            capacity=self.config.max_state_entries
        )
        self._uid_routes: OrderedDict[str, tuple[EncryptedKey, datetime]] = OrderedDict()
        self._finalized: BoundedEventDeduplicator[str] = BoundedEventDeduplicator(
            horizon=self.config.final_dedup_horizon,
            max_entries=self.config.final_dedup_capacity,
        )
        self._watermark: datetime | None = None
        self._last_cleanup_at: datetime | None = None
        self.uid_capacity_evictions = 0
        self.session_capacity_evictions = 0

    def __len__(self) -> int:
        return len(self._states)

    @property
    def capacity_evictions(self) -> int:
        return self._states.capacity_evictions

    def get(self, key: EncryptedKey) -> EncryptedState | None:
        return self._states.get(key)

    def items(self) -> tuple[tuple[EncryptedKey, EncryptedState], ...]:
        """Return a stable read-only snapshot for periodic feature extraction."""

        return self._states.items()

    def key_for_uid(self, uid: str) -> EncryptedKey | None:
        route = self._uid_routes.get(uid)
        return route[0] if route is not None else None

    def update_protocol(self, observation: EncryptedProtocolObservation) -> bool:
        if not self._accept_time(observation.event_time):
            return False
        if self._finalized.contains(observation.zeek_uid):
            return False
        key: EncryptedKey = (
            observation.client_ip, observation.server_ip, observation.server_port,
            observation.ip_protocol, observation.security_family,
        )
        routed = self._uid_routes.get(observation.zeek_uid)
        if routed is not None and routed[0] != key:
            return False
        state = self._get_or_create_state(key, observation.event_time)
        bucket = state.buckets.bucket_for(observation.event_time)
        if bucket is None:
            return False
        session = state.active_sessions.get(observation.zeek_uid)
        newly_identified = routed is None
        if session is None:
            session = self._admit_session(state, observation.zeek_uid, observation.event_time)
        if newly_identified:
            self._admit_route(observation.zeek_uid, key, observation.event_time)
            bucket.session_starts += 1
        else:
            self._touch_route(observation.zeek_uid, key, observation.event_time)

        changed = self._merge_metadata(session, bucket, observation)
        session.last_seen = max(session.last_seen, observation.event_time)
        state.last_activity = max(state.last_activity, observation.event_time)
        state.active_sessions.move_to_end(observation.zeek_uid)
        self._states.touch(key)
        return newly_identified or changed

    def update_flow(self, update: DirectionalFlowUpdate) -> bool:
        if self._finalized.contains(update.zeek_uid):
            return False
        route = self._uid_routes.get(update.zeek_uid)
        if route is None or not self._accept_time(update.last_seen):
            return False
        key = route[0]
        state = self._states.get(key)
        if state is None:
            return False
        session = state.active_sessions.get(update.zeek_uid)
        if session is None:
            return False
        direction = self._direction(key, update)
        if direction is None:
            return False
        bucket = state.buckets.bucket_for(update.last_seen)
        if bucket is None:
            return False
        self._apply_traffic(bucket, session, direction, update.packet_delta, update.byte_delta)
        session.last_seen = max(session.last_seen, update.last_seen)
        state.last_activity = max(state.last_activity, update.last_seen)
        state.active_sessions.move_to_end(update.zeek_uid)
        self._touch_route(update.zeek_uid, key, update.last_seen)
        self._states.touch(key)
        return True

    def finalize(self, snapshot: FlowSnapshot) -> bool:
        route = self._uid_routes.get(snapshot.uid)
        if route is None or snapshot.kind != "final":
            return False
        if not self._finalized.accept(snapshot.uid, snapshot.observed_at):
            return False
        key = route[0]
        state = self._states.get(key)
        if state is None:
            self._uid_routes.pop(snapshot.uid, None)
            return False
        session = state.active_sessions.get(snapshot.uid)
        if session is None:
            self._uid_routes.pop(snapshot.uid, None)
            return False
        bucket = state.buckets.bucket_for(snapshot.observed_at)
        if bucket is None:
            return False
        final_c2s, final_s2c = self._snapshot_totals(key, snapshot)
        if final_c2s is None:
            return False
        c2s_packets, c2s_bytes = final_c2s
        s2c_packets, s2c_bytes = final_s2c
        self._apply_traffic(
            bucket, session, "client",
            max(0, c2s_packets - session.client_to_server_packets),
            max(0, c2s_bytes - session.client_to_server_ip_bytes),
        )
        self._apply_traffic(
            bucket, session, "server",
            max(0, s2c_packets - session.server_to_client_packets),
            max(0, s2c_bytes - session.server_to_client_ip_bytes),
        )
        end_time = snapshot.last_seen
        sample = EncryptedSessionSample(
            end_time=end_time,
            duration=max(0.0, (snapshot.last_seen - snapshot.first_seen).total_seconds()),
            client_to_server_packets=session.client_to_server_packets,
            client_to_server_ip_bytes=session.client_to_server_ip_bytes,
            server_to_client_packets=session.server_to_client_packets,
            server_to_client_ip_bytes=session.server_to_client_ip_bytes,
            directions_observed_mask=session.directions_observed_mask,
        )
        state.completed_sessions.insert(sample, watermark=snapshot.observed_at)
        session.last_seen = max(session.last_seen, snapshot.observed_at)
        self._touch_route(snapshot.uid, key, snapshot.observed_at)
        state.last_activity = max(state.last_activity, snapshot.observed_at)
        self._states.touch(key)
        return True

    def maybe_expire(self, now: datetime) -> int | None:
        if self._last_cleanup_at is None:
            self._last_cleanup_at = now
            return None
        if now < self._last_cleanup_at or now - self._last_cleanup_at < self.config.cleanup_interval:
            return None
        self._last_cleanup_at = now
        return self.expire(now)

    def expire(self, now: datetime) -> int:
        if self._watermark is None or now > self._watermark:
            self._watermark = now
        session_cutoff = now - self.config.session_timeout
        expired_states: list[EncryptedKey] = []
        for key, state in self._states.items():
            state.buckets.expire(now)
            state.completed_sessions.expire(now)
            expired_uids = [
                uid
                for uid, session in state.active_sessions.items()
                if session.last_seen
                <= now
                - (
                    self.config.final_dedup_horizon
                    if self._finalized.contains(uid)
                    else self.config.session_timeout
                )
            ]
            for uid in expired_uids:
                state.active_sessions.pop(uid, None)
                self._uid_routes.pop(uid, None)
            if (
                len(state.buckets) == 0 and not state.active_sessions
                and len(state.completed_sessions) == 0
                and state.last_activity <= now - self.config.inactivity_timeout
            ):
                expired_states.append(key)
        for key in expired_states:
            self._states.remove(key)
        self._finalized.expire(now)
        return len(expired_states)

    def _get_or_create_state(self, key: EncryptedKey, event_time: datetime) -> EncryptedState:
        state = self._states.get(key)
        if state is not None:
            return state
        if len(self._states) >= self.config.max_state_entries:
            evicted = self._states.evict_oldest()
            if evicted is not None:
                for uid in evicted[1].active_sessions:
                    self._uid_routes.pop(uid, None)
        return self._states.get_or_create(key, lambda: EncryptedState(
            event_time,
            BucketRing(window=self.config.window, bucket_width=self.config.bucket_width, factory=self._new_bucket),
            OrderedDict(),
            BoundedTimeDeque(
                horizon=self.config.completed_horizon,
                max_samples=self.config.completed_sample_capacity,
                timestamp=lambda sample: sample.end_time,
            ),
        ))

    def _admit_session(self, state: EncryptedState, uid: str, event_time: datetime) -> EncryptedSessionAccumulator:
        if len(state.active_sessions) >= self.config.sessions_per_state:
            evicted_uid, _ = state.active_sessions.popitem(last=False)
            self._uid_routes.pop(evicted_uid, None)
            self.session_capacity_evictions += 1
        session = EncryptedSessionAccumulator(uid, event_time, event_time, 0, 0, 0, 0, 0)
        state.active_sessions[uid] = session
        return session

    def _admit_route(self, uid: str, key: EncryptedKey, event_time: datetime) -> None:
        if len(self._uid_routes) >= self.config.uid_capacity:
            evicted_uid, (evicted_key, _) = self._uid_routes.popitem(last=False)
            evicted_state = self._states.get(evicted_key)
            if evicted_state is not None:
                evicted_state.active_sessions.pop(evicted_uid, None)
            self.uid_capacity_evictions += 1
        self._uid_routes[uid] = (key, event_time)

    def _touch_route(self, uid: str, key: EncryptedKey, event_time: datetime) -> None:
        self._uid_routes[uid] = (key, max(self._uid_routes[uid][1], event_time))
        self._uid_routes.move_to_end(uid)

    def _merge_metadata(self, session: EncryptedSessionAccumulator, bucket: EncryptedBucket, observation: EncryptedProtocolObservation) -> bool:
        changed = False
        if observation.kind == "metadata" and not session.metadata_seen & _FIELD_BITS["metadata_record"]:
            bucket.metadata_records += 1
            session.metadata_seen |= _FIELD_BITS["metadata_record"]
            changed = True
        categorical = (
            ("version", observation.version, bucket.version_counts, False),
            ("cipher", observation.cipher, bucket.cipher_counts, False),
            ("curve", observation.curve, bucket.curve_counts, False),
            ("alpn", observation.alpn, bucket.alpn_counts, False),
            ("server_name", observation.server_name, bucket.server_name_hashes, True),
            ("server_cert_fingerprint", observation.server_cert_fingerprint, bucket.server_cert_fingerprints, False),
            ("client_fingerprint", observation.client_fingerprint, bucket.client_fingerprints, False),
        )
        for field, value, counter, hashed in categorical:
            bit = _FIELD_BITS[field]
            if value is not None and not session.metadata_seen & bit:
                normalized = value.lower().removesuffix(".") if field == "server_name" else value
                limited = normalized[: self.config.category_length_limit]
                counter.add(stable_digest(limited) if hashed else limited, 1)
                session.metadata_seen |= bit
                changed = True
        if observation.resumed is not None and not session.metadata_seen & _FIELD_BITS["resumed"]:
            if observation.resumed:
                bucket.resumed_count += 1
            session.metadata_seen |= _FIELD_BITS["resumed"]
            changed = True
        if observation.established is not None and not session.metadata_seen & _FIELD_BITS["established"]:
            if observation.established:
                bucket.established_count += 1
            else:
                bucket.failed_or_incomplete_count += 1
            session.metadata_seen |= _FIELD_BITS["established"]
            changed = True
        if observation.last_alert is not None and not session.metadata_seen & _FIELD_BITS["last_alert"]:
            bucket.alert_count += 1
            session.metadata_seen |= _FIELD_BITS["last_alert"]
            changed = True
        return changed

    @staticmethod
    def _direction(key: EncryptedKey, update: DirectionalFlowUpdate) -> str | None:
        client_ip, server_ip, server_port, protocol, _ = key
        if update.key.protocol != protocol:
            return None
        if update.key.src_ip == client_ip and update.key.dst_ip == server_ip and update.key.dst_port == server_port:
            return "client"
        if update.key.src_ip == server_ip and update.key.src_port == server_port and update.key.dst_ip == client_ip:
            return "server"
        return None

    @staticmethod
    def _apply_traffic(bucket: EncryptedBucket, session: EncryptedSessionAccumulator, direction: str, packets: int, ip_bytes: int) -> None:
        if packets == 0 and ip_bytes == 0:
            return
        if direction == "client":
            bucket.client_to_server_packets += packets
            bucket.client_to_server_ip_bytes += ip_bytes
            session.client_to_server_packets += packets
            session.client_to_server_ip_bytes += ip_bytes
            session.directions_observed_mask |= 1
        else:
            bucket.server_to_client_packets += packets
            bucket.server_to_client_ip_bytes += ip_bytes
            session.server_to_client_packets += packets
            session.server_to_client_ip_bytes += ip_bytes
            session.directions_observed_mask |= 2

    @staticmethod
    def _snapshot_totals(key: EncryptedKey, snapshot: FlowSnapshot) -> tuple[tuple[int, int], tuple[int, int]] | tuple[None, None]:
        client_ip, server_ip, server_port, protocol, _ = key
        if snapshot.ip_proto != protocol:
            return None, None
        if snapshot.orig_h == client_ip and snapshot.resp_h == server_ip and snapshot.resp_p == server_port:
            return (snapshot.orig_pkts, snapshot.orig_ip_bytes), (snapshot.resp_pkts, snapshot.resp_ip_bytes)
        if snapshot.resp_h == client_ip and snapshot.orig_h == server_ip and snapshot.orig_p == server_port:
            return (snapshot.resp_pkts, snapshot.resp_ip_bytes), (snapshot.orig_pkts, snapshot.orig_ip_bytes)
        return None, None

    def _accept_time(self, event_time: datetime) -> bool:
        if self._watermark is not None and event_time < self._watermark - self.config.window:
            return False
        if self._watermark is None or event_time > self._watermark:
            self._watermark = event_time
        return True

    def _new_bucket(self, start: datetime) -> EncryptedBucket:
        counter = lambda: BoundedCounterMap(capacity=self.config.category_capacity, zero=0)
        return EncryptedBucket(start, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            counter(), counter(), counter(), counter(), counter(), counter(), counter())

    def _validate_config(self) -> None:
        durations = (
            self.config.window, self.config.bucket_width, self.config.completed_horizon,
            self.config.session_timeout, self.config.inactivity_timeout,
            self.config.cleanup_interval, self.config.final_dedup_horizon,
        )
        capacities = (
            self.config.completed_sample_capacity, self.config.max_state_entries,
            self.config.sessions_per_state, self.config.uid_capacity,
            self.config.category_capacity, self.config.final_dedup_capacity,
            self.config.category_length_limit,
        )
        if any(value <= timedelta(0) for value in durations):
            raise ValueError("encrypted-state durations must be positive")
        if any(value <= 0 for value in capacities):
            raise ValueError("encrypted-state capacities must be positive")
