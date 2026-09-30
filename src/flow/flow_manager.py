"""Dictionary-backed management of compact directional flow state."""

from __future__ import annotations

from datetime import datetime, timedelta
from types import MappingProxyType
from typing import Mapping

from src.flow.models import DirectionalFlowUpdate, FlowKey, FlowState


class FlowManager:
    """Aggregate directional updates and expire inactive FlowStates."""

    def __init__(
        self,
        *,
        inactivity_timeout: timedelta,
        cleanup_interval: timedelta,
    ) -> None:
        if inactivity_timeout <= timedelta(0):
            raise ValueError("inactivity timeout must be positive")
        if cleanup_interval <= timedelta(0):
            raise ValueError("cleanup interval must be positive")

        self.inactivity_timeout = inactivity_timeout
        self.cleanup_interval = cleanup_interval
        self._flows: dict[FlowKey, FlowState] = {}
        self._last_cleanup_at: datetime | None = None

    def __len__(self) -> int:
        return len(self._flows)

    @property
    def active_flows(self) -> Mapping[FlowKey, FlowState]:
        return MappingProxyType(self._flows)

    def update(self, update: DirectionalFlowUpdate) -> FlowState:
        state = self._flows.get(update.key)
        if state is None:
            state = FlowState.from_update(update)
            self._flows[update.key] = state
        else:
            state.apply(update)
        return state

    def get(self, key: FlowKey) -> FlowState | None:
        return self._flows.get(key)

    def inspect(self) -> tuple[FlowState, ...]:
        """Return a stable, deterministic view of current active flows."""

        return tuple(
            sorted(
                self._flows.values(),
                key=lambda state: (
                    str(state.key.src_ip),
                    state.key.src_port,
                    str(state.key.dst_ip),
                    state.key.dst_port,
                    state.key.protocol,
                ),
            )
        )

    def expire_inactive(self, now: datetime) -> tuple[FlowState, ...]:
        cutoff = now - self.inactivity_timeout
        expired_keys = [
            key for key, state in self._flows.items() if state.last_seen <= cutoff
        ]
        return tuple(self._flows.pop(key) for key in expired_keys)

    def maybe_expire(self, now: datetime) -> tuple[FlowState, ...] | None:
        """Run an expiration scan only when the cleanup interval is due."""

        if self._last_cleanup_at is None:
            self._last_cleanup_at = now
            return None
        if now < self._last_cleanup_at:
            return None
        if now - self._last_cleanup_at < self.cleanup_interval:
            return None

        self._last_cleanup_at = now
        return self.expire_inactive(now)
