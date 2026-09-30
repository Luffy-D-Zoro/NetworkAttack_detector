"""Bounded directional timing state for future beacon features."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timedelta

from src.flow.models import DirectionalConnectionEvent, DirectionalFlowUpdate
from src.states.common import BoundedTimeDeque, CappedStateTable

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
BeaconKey = tuple[IPAddress, IPAddress, int, int]


@dataclass(frozen=True, slots=True)
class EpisodeSample:
    start_time: datetime
    last_time: datetime
    packets: int
    ip_bytes: int


@dataclass(frozen=True, slots=True)
class ConnectionSample:
    end_time: datetime
    duration: timedelta
    packets: int
    ip_bytes: int


@dataclass(slots=True)
class BeaconState:
    last_activity: datetime
    current_episode: EpisodeSample | None
    episodes: BoundedTimeDeque[EpisodeSample]
    connection_starts: BoundedTimeDeque[datetime]
    completed_connections: BoundedTimeDeque[ConnectionSample]


@dataclass(frozen=True, slots=True)
class BeaconStateConfig:
    horizon: timedelta = timedelta(hours=24)
    episode_gap: timedelta = timedelta(seconds=60)
    inactivity_timeout: timedelta = timedelta(hours=48)
    cleanup_interval: timedelta = timedelta(seconds=30)
    max_state_entries: int = 50_000
    episode_max_samples: int = 4_096
    connection_start_max_samples: int = 4_096
    completed_connection_max_samples: int = 4_096


class BeaconStateManager:
    """Maintain bounded timing/size histories keyed without source port."""

    def __init__(self, config: BeaconStateConfig | None = None) -> None:
        self.config = config or BeaconStateConfig()
        self._validate_config()
        self._states: CappedStateTable[BeaconKey, BeaconState] = CappedStateTable(
            capacity=self.config.max_state_entries
        )
        self._watermark: datetime | None = None
        self._last_cleanup_at: datetime | None = None

    def __len__(self) -> int:
        return len(self._states)

    @property
    def capacity_evictions(self) -> int:
        return self._states.capacity_evictions

    def get(self, key: BeaconKey) -> BeaconState | None:
        return self._states.get(key)

    def items(self) -> tuple[tuple[BeaconKey, BeaconState], ...]:
        """Return a stable read-only snapshot for periodic feature extraction."""

        return self._states.items()

    def update_flow(self, update: DirectionalFlowUpdate) -> bool:
        event_time = update.last_seen
        state_key = self._key(update.key.src_ip, update.key.dst_ip, update.key.dst_port, update.key.protocol)
        state = self._state_for(state_key, event_time)
        if state is None:
            return False
        self._add_episode_observation(
            state,
            event_time,
            update.packet_delta,
            update.byte_delta,
        )
        return True

    def update_connection(self, event: DirectionalConnectionEvent) -> bool:
        state_key = self._key(
            event.key.src_ip,
            event.key.dst_ip,
            event.key.dst_port,
            event.key.protocol,
        )
        state = self._state_for(state_key, event.event_time)
        if state is None:
            return False
        watermark = self._watermark or event.event_time

        if event.kind == "start":
            state.connection_starts.insert(event.first_seen, watermark=watermark)
            return True

        state.completed_connections.insert(
            ConnectionSample(
                end_time=event.last_seen,
                duration=event.last_seen - event.first_seen,
                packets=event.total_packets,
                ip_bytes=event.total_ip_bytes,
            ),
            watermark=watermark,
        )
        if (
            state.current_episode is not None
            and event.last_seen >= state.current_episode.last_time
            and event.event_time - state.current_episode.last_time
            > self.config.episode_gap
        ):
            self._close_current_episode(state, watermark=watermark)
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
        expired: list[BeaconKey] = []
        for state_key, state in self._states.items():
            if (
                state.current_episode is not None
                and now - state.current_episode.last_time > self.config.episode_gap
            ):
                self._close_current_episode(state, watermark=now)

            state.episodes.expire(now)
            state.connection_starts.expire(now)
            state.completed_connections.expire(now)
            if (
                state.current_episode is None
                and len(state.episodes) == 0
                and len(state.connection_starts) == 0
                and len(state.completed_connections) == 0
                and state.last_activity <= now - self.config.inactivity_timeout
            ):
                expired.append(state_key)
        for state_key in expired:
            self._states.remove(state_key)
        return len(expired)

    def _state_for(
        self, state_key: BeaconKey, event_time: datetime
    ) -> BeaconState | None:
        if not self._accept_event_time(event_time):
            return None
        state = self._states.get(state_key)
        if state is None:
            state = self._states.get_or_create(
                state_key,
                lambda: BeaconState(
                    last_activity=event_time,
                    current_episode=None,
                    episodes=BoundedTimeDeque(
                        horizon=self.config.horizon,
                        max_samples=self.config.episode_max_samples,
                        timestamp=lambda sample: sample.last_time,
                    ),
                    connection_starts=BoundedTimeDeque(
                        horizon=self.config.horizon,
                        max_samples=self.config.connection_start_max_samples,
                        timestamp=lambda timestamp: timestamp,
                    ),
                    completed_connections=BoundedTimeDeque(
                        horizon=self.config.horizon,
                        max_samples=self.config.completed_connection_max_samples,
                        timestamp=lambda sample: sample.end_time,
                    ),
                ),
            )
        state.last_activity = max(state.last_activity, event_time)
        self._states.touch(state_key)
        return state

    def _accept_event_time(self, event_time: datetime) -> bool:
        if (
            self._watermark is not None
            and event_time < self._watermark - self.config.horizon
        ):
            return False
        if self._watermark is None or event_time > self._watermark:
            self._watermark = event_time
        return True

    def _add_episode_observation(
        self,
        state: BeaconState,
        event_time: datetime,
        packets: int,
        ip_bytes: int,
    ) -> None:
        observation = EpisodeSample(event_time, event_time, packets, ip_bytes)
        current = state.current_episode
        watermark = self._watermark or event_time

        if current is None:
            completed = tuple(state.episodes)
            if not completed or event_time - completed[-1].last_time > self.config.episode_gap:
                state.current_episode = observation
            else:
                self._merge_late_observation(state, observation, keep_current=False)
            return

        if event_time >= current.last_time:
            if event_time - current.last_time <= self.config.episode_gap:
                state.current_episode = EpisodeSample(
                    start_time=current.start_time,
                    last_time=event_time,
                    packets=current.packets + packets,
                    ip_bytes=current.ip_bytes + ip_bytes,
                )
            else:
                self._close_current_episode(state, watermark=watermark)
                state.current_episode = observation
            return

        self._merge_late_observation(state, observation, keep_current=True)

    def _merge_late_observation(
        self,
        state: BeaconState,
        observation: EpisodeSample,
        *,
        keep_current: bool,
    ) -> None:
        samples = list(state.episodes)
        if state.current_episode is not None:
            samples.append(state.current_episode)
        samples.append(observation)
        samples.sort(key=lambda sample: (sample.start_time, sample.last_time))

        merged: list[EpisodeSample] = []
        for sample in samples:
            if not merged or sample.start_time - merged[-1].last_time > self.config.episode_gap:
                merged.append(sample)
                continue
            previous = merged[-1]
            merged[-1] = EpisodeSample(
                start_time=min(previous.start_time, sample.start_time),
                last_time=max(previous.last_time, sample.last_time),
                packets=previous.packets + sample.packets,
                ip_bytes=previous.ip_bytes + sample.ip_bytes,
            )

        if keep_current:
            state.current_episode = merged.pop()
        else:
            state.current_episode = None
        state.episodes.replace(
            iter(merged),
            watermark=self._watermark or observation.last_time,
        )

    def _close_current_episode(
        self, state: BeaconState, *, watermark: datetime
    ) -> None:
        if state.current_episode is None:
            return
        state.episodes.insert(state.current_episode, watermark=watermark)
        state.current_episode = None

    @staticmethod
    def _key(
        src_ip: IPAddress,
        dst_ip: IPAddress,
        dst_port: int,
        protocol: int,
    ) -> BeaconKey:
        return (src_ip, dst_ip, dst_port, protocol)

    def _validate_config(self) -> None:
        durations = (
            self.config.horizon,
            self.config.episode_gap,
            self.config.inactivity_timeout,
            self.config.cleanup_interval,
        )
        capacities = (
            self.config.max_state_entries,
            self.config.episode_max_samples,
            self.config.connection_start_max_samples,
            self.config.completed_connection_max_samples,
        )
        if any(value <= timedelta(0) for value in durations):
            raise ValueError("beacon durations must be positive")
        if self.config.episode_gap > self.config.horizon:
            raise ValueError("beacon episode gap must not exceed its horizon")
        if any(value <= 0 for value in capacities):
            raise ValueError("beacon capacities must be positive")
