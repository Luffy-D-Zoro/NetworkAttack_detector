"""Shared event-time windows and bounded-capacity state primitives."""

from __future__ import annotations

import hashlib
import json
import math
from collections import OrderedDict, deque
from collections.abc import Callable, Iterator, Mapping
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from typing import Generic, TypeVar

K = TypeVar("K")
V = TypeVar("V")
B = TypeVar("B")


class BucketRing(Generic[B]):
    """Bounded fixed-width buckets indexed by event time."""

    def __init__(
        self,
        *,
        window: timedelta,
        bucket_width: timedelta,
        factory: Callable[[datetime], B],
    ) -> None:
        if window <= timedelta(0) or bucket_width <= timedelta(0):
            raise ValueError("window and bucket width must be positive")
        self.window = window
        self.bucket_width = bucket_width
        self._width_seconds = bucket_width.total_seconds()
        self.max_buckets = math.ceil(window / bucket_width) + 1
        self._factory = factory
        self._buckets: dict[int, B] = {}
        self._watermark: datetime | None = None

    def __len__(self) -> int:
        return len(self._buckets)

    @property
    def watermark(self) -> datetime | None:
        return self._watermark

    def __iter__(self) -> Iterator[B]:
        for index in sorted(self._buckets):
            yield self._buckets[index]

    def bucket_for(self, event_time: datetime) -> B | None:
        event_time = _utc(event_time)
        if self._watermark is not None and event_time < self._watermark - self.window:
            return None
        if self._watermark is None or event_time > self._watermark:
            self._watermark = event_time

        index = math.floor(event_time.timestamp() / self._width_seconds)
        bucket = self._buckets.get(index)
        if bucket is not None:
            return bucket

        # Retain the configured +1 boundary bucket while preventing sparse
        # event streams from accumulating obsolete indices between cleanups.
        if len(self._buckets) >= self.max_buckets:
            self.expire(self._watermark)
        if len(self._buckets) >= self.max_buckets:
            del self._buckets[min(self._buckets)]

        bucket_start = datetime.fromtimestamp(index * self._width_seconds, tz=UTC)
        bucket = self._factory(bucket_start)
        self._buckets[index] = bucket
        return bucket

    def expire(self, now: datetime) -> int:
        now = _utc(now)
        if self._watermark is None or now > self._watermark:
            self._watermark = now
        cutoff = now - self.window
        expired = [
            index
            for index in self._buckets
            if datetime.fromtimestamp(
                (index + 1) * self._width_seconds, tz=UTC
            )
            <= cutoff
        ]
        for index in expired:
            del self._buckets[index]
        return len(expired)


class BoundedCounterMap(Generic[K, V]):
    """Retain known counters and aggregate unseen keys after saturation."""

    def __init__(self, *, capacity: int, zero: V) -> None:
        if capacity <= 0:
            raise ValueError("counter-map capacity must be positive")
        self.capacity = capacity
        self._zero = zero
        self._values: dict[K, V] = {}
        self.overflow_count = 0
        self.overflow_value = zero

    def __len__(self) -> int:
        return len(self._values)

    @property
    def values(self) -> Mapping[K, V]:
        return MappingProxyType(self._values)

    @property
    def saturated(self) -> bool:
        return self.overflow_count > 0

    def add(self, key: K, value: V) -> bool:
        if key in self._values:
            self._values[key] = self._values[key] + value  # type: ignore[operator]
            return True
        if len(self._values) < self.capacity:
            self._values[key] = self._zero + value  # type: ignore[operator]
            return True
        self.overflow_count += 1
        self.overflow_value = self.overflow_value + value  # type: ignore[operator]
        return False


def _stable_digest(value: object) -> bytes:
    normalized = json.dumps(
        value,
        default=str,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.blake2b(normalized, digest_size=16).digest()


def stable_digest(value: object) -> bytes:
    """Return the project's stable BLAKE2b-128 correlation digest."""

    return _stable_digest(value)


class BoundedHashSet:
    """Store only stable 128-bit digests and expose overflow observations."""

    def __init__(self, *, capacity: int) -> None:
        if capacity <= 0:
            raise ValueError("hash-set capacity must be positive")
        self.capacity = capacity
        self._digests: set[bytes] = set()
        self.overflow_count = 0

    def __len__(self) -> int:
        return len(self._digests)

    @property
    def saturated(self) -> bool:
        return self.overflow_count > 0

    @property
    def digests(self) -> frozenset[bytes]:
        """Expose immutable digests for bounded cross-bucket cardinality."""

        return frozenset(self._digests)

    def add(self, value: object) -> bool:
        digest = _stable_digest(value)
        if digest in self._digests:
            return False
        if len(self._digests) < self.capacity:
            self._digests.add(digest)
            return True
        self.overflow_count += 1
        return False


class CappedStateTable(Generic[K, V]):
    """O(1) LRU admission for top-level manager state."""

    def __init__(self, *, capacity: int) -> None:
        if capacity <= 0:
            raise ValueError("state-table capacity must be positive")
        self.capacity = capacity
        self._values: OrderedDict[K, V] = OrderedDict()
        self.capacity_evictions = 0

    def __len__(self) -> int:
        return len(self._values)

    def get(self, key: K) -> V | None:
        return self._values.get(key)

    def get_or_create(self, key: K, factory: Callable[[], V]) -> V:
        value = self._values.get(key)
        if value is not None:
            self._values.move_to_end(key)
            return value
        if len(self._values) >= self.capacity:
            self._values.popitem(last=False)
            self.capacity_evictions += 1
        value = factory()
        self._values[key] = value
        return value

    def touch(self, key: K) -> None:
        self._values.move_to_end(key)

    def remove(self, key: K) -> V:
        return self._values.pop(key)

    def items(self) -> tuple[tuple[K, V], ...]:
        return tuple(self._values.items())

    def evict_oldest(self) -> tuple[K, V] | None:
        """Explicitly evict the LRU entry for managers with join cleanup."""

        if not self._values:
            return None
        self.capacity_evictions += 1
        return self._values.popitem(last=False)


class BoundedEventDeduplicator(Generic[K]):
    """Bound signal identity by both event-time horizon and entry count."""

    def __init__(self, *, horizon: timedelta, max_entries: int) -> None:
        if horizon <= timedelta(0) or max_entries <= 0:
            raise ValueError("dedup horizon and maximum entries must be positive")
        self.horizon = horizon
        self.max_entries = max_entries
        self._seen: OrderedDict[K, datetime] = OrderedDict()
        self._watermark: datetime | None = None
        self.capacity_evictions = 0

    def __len__(self) -> int:
        return len(self._seen)

    def contains(self, key: K) -> bool:
        return key in self._seen

    def accept(self, key: K, event_time: datetime) -> bool:
        event_time = _utc(event_time)
        if self._watermark is not None and event_time < self._watermark - self.horizon:
            return False
        if self._watermark is None or event_time > self._watermark:
            self._watermark = event_time
        if key in self._seen:
            return False
        if len(self._seen) >= self.max_entries:
            self._seen.popitem(last=False)
            self.capacity_evictions += 1
        self._seen[key] = event_time
        return True

    def expire(self, now: datetime) -> int:
        now = _utc(now)
        if self._watermark is None or now > self._watermark:
            self._watermark = now
        cutoff = now - self.horizon
        expired = [key for key, timestamp in self._seen.items() if timestamp <= cutoff]
        for key in expired:
            del self._seen[key]
        return len(expired)


class BoundedTimeDeque(Generic[V]):
    """Timestamp-ordered samples bounded by both horizon and count."""

    def __init__(
        self,
        *,
        horizon: timedelta,
        max_samples: int,
        timestamp: Callable[[V], datetime],
    ) -> None:
        if horizon <= timedelta(0) or max_samples <= 0:
            raise ValueError("sample horizon and maximum count must be positive")
        self.horizon = horizon
        self.max_samples = max_samples
        self._timestamp = timestamp
        self._values: deque[V] = deque()

    def __len__(self) -> int:
        return len(self._values)

    def __iter__(self) -> Iterator[V]:
        return iter(self._values)

    def insert(self, value: V, *, watermark: datetime) -> bool:
        """Insert in timestamp order; reject samples older than the horizon."""

        watermark = _utc(watermark)
        value_time = _utc(self._timestamp(value))
        if value_time < watermark - self.horizon:
            return False

        if not self._values or value_time >= _utc(self._timestamp(self._values[-1])):
            self._values.append(value)
        else:
            values = list(self._values)
            index = len(values)
            while index > 0 and value_time < _utc(self._timestamp(values[index - 1])):
                index -= 1
            values.insert(index, value)
            self._values = deque(values)

        self.expire(watermark)
        while len(self._values) > self.max_samples:
            self._values.popleft()
        return any(retained is value for retained in self._values)

    def replace(self, values: Iterator[V], *, watermark: datetime) -> None:
        """Replace with ordered bounded values, used for rare late merges."""

        self._values.clear()
        for value in values:
            self.insert(value, watermark=watermark)

    def expire(self, now: datetime) -> int:
        now = _utc(now)
        cutoff = now - self.horizon
        removed = 0
        while self._values and _utc(self._timestamp(self._values[0])) < cutoff:
            self._values.popleft()
            removed += 1
        while len(self._values) > self.max_samples:
            self._values.popleft()
            removed += 1
        return removed


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
