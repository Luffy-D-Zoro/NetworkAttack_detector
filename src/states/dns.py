"""Bounded source-wide and registrable-domain DNS observation state."""

from __future__ import annotations

import ipaddress
import math
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta

import tldextract

from src.ingestion.zeek_websocket import DNSQueryObservation, DNSResultObservation
from src.states.common import (
    BoundedCounterMap,
    BoundedEventDeduplicator,
    BoundedHashSet,
    BucketRing,
    CappedStateTable,
    stable_digest,
)

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

_PSL = tldextract.TLDExtract(
    suffix_list_urls=(),
    cache_dir=None,
    fallback_to_snapshot=True,
    include_psl_private_domains=True,
)


@dataclass(slots=True)
class DNSSourceBucket:
    bucket_start: datetime
    query_count: int
    query_length_sum: int
    query_length_sum_squares: int
    max_query_length: int
    label_count_sum: int
    malformed_query_count: int
    qtype_counts: BoundedCounterMap[int, int]
    qclass_counts: BoundedCounterMap[int, int]
    unique_qname_hashes: BoundedHashSet
    unique_base_domain_hashes: BoundedHashSet
    result_count: int
    reply_count: int
    no_reply_count: int
    rejected_count: int
    rcode_counts: BoundedCounterMap[int, int]
    rtt_sum: float
    rtt_sum_squares: float
    rtt_count: int
    answer_count_sum: int

    @property
    def qname_hash_overflow(self) -> int:
        return self.unique_qname_hashes.overflow_count

    @property
    def base_domain_hash_overflow(self) -> int:
        return self.unique_base_domain_hashes.overflow_count


@dataclass(slots=True)
class DNSDomainBucket:
    bucket_start: datetime
    query_count: int
    subdomain_length_sum: int
    subdomain_length_sum_squares: int
    max_subdomain_length: int
    subdomain_entropy_sum: float
    subdomain_entropy_sum_squares: float
    max_subdomain_entropy: float
    unique_subdomain_hashes: BoundedHashSet
    qtype_counts: BoundedCounterMap[int, int]

    @property
    def subdomain_hash_overflow(self) -> int:
        return self.unique_subdomain_hashes.overflow_count


@dataclass(slots=True)
class DNSDomainWindow:
    last_activity: datetime
    buckets: BucketRing[DNSDomainBucket]


@dataclass(slots=True)
class DNSState:
    last_activity: datetime
    source_buckets: BucketRing[DNSSourceBucket]
    domains: dict[str, DNSDomainWindow]
    domain_overflow: DNSDomainWindow


@dataclass(frozen=True, slots=True)
class DNSStateConfig:
    source_window: timedelta = timedelta(minutes=10)
    source_bucket_width: timedelta = timedelta(seconds=30)
    domain_window: timedelta = timedelta(minutes=30)
    domain_bucket_width: timedelta = timedelta(minutes=1)
    inactivity_timeout: timedelta = timedelta(hours=1)
    domain_inactivity_timeout: timedelta = timedelta(hours=1)
    cleanup_interval: timedelta = timedelta(seconds=30)
    max_state_entries: int = 50_000
    domain_capacity: int = 1_024
    category_capacity: int = 256
    qname_hash_capacity: int = 4_096
    domain_hash_capacity: int = 1_024
    subdomain_hash_capacity: int = 4_096
    dedup_horizon: timedelta = timedelta(minutes=30)
    dedup_max_entries: int = 200_000


class DNSStateManager:
    """Maintain DNS state keyed by source IP with offline PSL grouping."""

    def __init__(self, config: DNSStateConfig | None = None) -> None:
        self.config = config or DNSStateConfig()
        self._validate_config()
        self._states: CappedStateTable[IPAddress, DNSState] = CappedStateTable(
            capacity=self.config.max_state_entries
        )
        self._dedup: BoundedEventDeduplicator[bytes] = BoundedEventDeduplicator(
            horizon=self.config.dedup_horizon,
            max_entries=self.config.dedup_max_entries,
        )
        self._watermark: datetime | None = None
        self._last_cleanup_at: datetime | None = None

    def __len__(self) -> int:
        return len(self._states)

    @property
    def capacity_evictions(self) -> int:
        return self._states.capacity_evictions

    @property
    def dedup_capacity_evictions(self) -> int:
        return self._dedup.capacity_evictions

    def get(self, source_ip: IPAddress) -> DNSState | None:
        return self._states.get(source_ip)

    def items(self) -> tuple[tuple[IPAddress, DNSState], ...]:
        """Return a stable read-only snapshot for periodic feature extraction."""

        return self._states.items()

    def update_query(self, observation: DNSQueryObservation) -> bool:
        normalized = observation.query.lower()
        if normalized.endswith("."):
            normalized = normalized[:-1]
        identity = stable_digest((
            "query", observation.zeek_uid, observation.transaction_id,
            normalized, observation.event_time,
        ))
        if not self._dedup.accept(identity, observation.event_time):
            return False

        state = self._state(observation.source_ip, observation.event_time)
        if state is None:
            return False
        source_bucket = state.source_buckets.bucket_for(observation.event_time)

        length = len(normalized.encode("utf-8"))
        labels = normalized.split(".") if normalized else []
        if source_bucket is not None:
            source_bucket.query_count += 1
            source_bucket.query_length_sum += length
            source_bucket.query_length_sum_squares += length * length
            source_bucket.max_query_length = max(source_bucket.max_query_length, length)
            source_bucket.label_count_sum += len(labels)
            source_bucket.qtype_counts.add(observation.qtype, 1)
            source_bucket.qclass_counts.add(observation.qclass, 1)
            source_bucket.unique_qname_hashes.add(normalized)

        if self._malformed(normalized, labels):
            if source_bucket is not None:
                source_bucket.malformed_query_count += 1
            return source_bucket is not None

        registrable, subdomain = self._domain_parts(normalized)
        if source_bucket is not None:
            source_bucket.unique_base_domain_hashes.add(registrable)
        domain = state.domains.get(registrable)
        if domain is None:
            if len(state.domains) < self.config.domain_capacity:
                domain = self._new_domain(observation.event_time)
                state.domains[registrable] = domain
            else:
                domain = state.domain_overflow
        bucket = domain.buckets.bucket_for(observation.event_time)
        if bucket is not None:
            subdomain_length = len(subdomain.encode("utf-8"))
            entropy = self._entropy(subdomain)
            bucket.query_count += 1
            bucket.subdomain_length_sum += subdomain_length
            bucket.subdomain_length_sum_squares += subdomain_length * subdomain_length
            bucket.max_subdomain_length = max(bucket.max_subdomain_length, subdomain_length)
            bucket.subdomain_entropy_sum += entropy
            bucket.subdomain_entropy_sum_squares += entropy * entropy
            bucket.max_subdomain_entropy = max(bucket.max_subdomain_entropy, entropy)
            bucket.unique_subdomain_hashes.add(subdomain)
            bucket.qtype_counts.add(observation.qtype, 1)
            domain.last_activity = max(domain.last_activity, observation.event_time)
        return source_bucket is not None or bucket is not None

    def update_result(self, observation: DNSResultObservation) -> bool:
        normalized = (observation.query or "").lower()
        if normalized.endswith("."):
            normalized = normalized[:-1]
        identity = stable_digest((
            "result", observation.zeek_uid, observation.transaction_id,
            normalized, observation.query_time,
        ))
        if not self._dedup.accept(identity, observation.result_time):
            return False
        if (
            self._watermark is not None
            and observation.result_time < self._watermark - self.config.source_window
        ):
            return False
        state = self._state(observation.source_ip, observation.result_time)
        if state is None:
            return False
        bucket = state.source_buckets.bucket_for(observation.result_time)
        if bucket is None:
            return False
        bucket.result_count += 1
        if observation.saw_reply:
            bucket.reply_count += 1
        else:
            bucket.no_reply_count += 1
        if observation.rejected:
            bucket.rejected_count += 1
        if observation.rcode is not None:
            bucket.rcode_counts.add(observation.rcode, 1)
        if observation.rtt is not None:
            bucket.rtt_sum += observation.rtt
            bucket.rtt_sum_squares += observation.rtt * observation.rtt
            bucket.rtt_count += 1
        if observation.answer_count is not None:
            bucket.answer_count_sum += observation.answer_count
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
        expired_sources: list[IPAddress] = []
        for source_ip, state in self._states.items():
            state.source_buckets.expire(now)
            expired_domains: list[str] = []
            for domain_name, domain in state.domains.items():
                domain.buckets.expire(now)
                if len(domain.buckets) == 0 and domain.last_activity <= now - self.config.domain_inactivity_timeout:
                    expired_domains.append(domain_name)
            for domain_name in expired_domains:
                del state.domains[domain_name]
            state.domain_overflow.buckets.expire(now)
            if (
                len(state.source_buckets) == 0
                and not state.domains
                and len(state.domain_overflow.buckets) == 0
                and state.last_activity <= now - self.config.inactivity_timeout
            ):
                expired_sources.append(source_ip)
        for source_ip in expired_sources:
            self._states.remove(source_ip)
        self._dedup.expire(now)
        return len(expired_sources)

    def _state(self, source_ip: IPAddress, event_time: datetime) -> DNSState | None:
        horizon = max(self.config.source_window, self.config.domain_window)
        if self._watermark is not None and event_time < self._watermark - horizon:
            return None
        if self._watermark is None or event_time > self._watermark:
            self._watermark = event_time
        state = self._states.get(source_ip)
        if state is None:
            state = self._states.get_or_create(source_ip, lambda: DNSState(
                last_activity=event_time,
                source_buckets=self._new_source_ring(),
                domains={},
                domain_overflow=self._new_domain(event_time),
            ))
        state.last_activity = max(state.last_activity, event_time)
        self._states.touch(source_ip)
        return state

    @staticmethod
    def _malformed(normalized: str, labels: list[str]) -> bool:
        if not normalized or any(not label for label in labels):
            return True
        encoded = [label.encode("utf-8") for label in labels]
        return any(len(label) > 63 for label in encoded) or sum(map(len, encoded)) + len(labels) + 1 > 255

    @staticmethod
    def _domain_parts(normalized: str) -> tuple[str, str]:
        extracted = _PSL(normalized)
        registrable = extracted.top_domain_under_public_suffix
        if not registrable:
            registrable = extracted.domain or normalized
        return registrable.lower(), extracted.subdomain.lower()

    @staticmethod
    def _entropy(value: str) -> float:
        if not value:
            return 0.0
        counts = Counter(value.encode("utf-8"))
        length = len(value.encode("utf-8"))
        return -sum((count / length) * math.log2(count / length) for count in counts.values())

    def _new_source_ring(self) -> BucketRing[DNSSourceBucket]:
        return BucketRing(window=self.config.source_window, bucket_width=self.config.source_bucket_width, factory=self._new_source_bucket)

    def _new_domain(self, event_time: datetime) -> DNSDomainWindow:
        return DNSDomainWindow(event_time, BucketRing(window=self.config.domain_window, bucket_width=self.config.domain_bucket_width, factory=self._new_domain_bucket))

    def _new_source_bucket(self, start: datetime) -> DNSSourceBucket:
        return DNSSourceBucket(
            start, 0, 0, 0, 0, 0, 0,
            BoundedCounterMap(capacity=self.config.category_capacity, zero=0),
            BoundedCounterMap(capacity=self.config.category_capacity, zero=0),
            BoundedHashSet(capacity=self.config.qname_hash_capacity),
            BoundedHashSet(capacity=self.config.domain_hash_capacity),
            0, 0, 0, 0,
            BoundedCounterMap(capacity=self.config.category_capacity, zero=0),
            0.0, 0.0, 0, 0,
        )

    def _new_domain_bucket(self, start: datetime) -> DNSDomainBucket:
        return DNSDomainBucket(
            start, 0, 0, 0, 0, 0.0, 0.0, 0.0,
            BoundedHashSet(capacity=self.config.subdomain_hash_capacity),
            BoundedCounterMap(capacity=self.config.category_capacity, zero=0),
        )

    def _validate_config(self) -> None:
        durations = (
            self.config.source_window, self.config.source_bucket_width,
            self.config.domain_window, self.config.domain_bucket_width,
            self.config.inactivity_timeout, self.config.domain_inactivity_timeout,
            self.config.cleanup_interval, self.config.dedup_horizon,
        )
        capacities = (
            self.config.max_state_entries, self.config.domain_capacity,
            self.config.category_capacity, self.config.qname_hash_capacity,
            self.config.domain_hash_capacity, self.config.subdomain_hash_capacity,
            self.config.dedup_max_entries,
        )
        if any(value <= timedelta(0) for value in durations):
            raise ValueError("DNS durations must be positive")
        if any(value <= 0 for value in capacities):
            raise ValueError("DNS capacities must be positive")
