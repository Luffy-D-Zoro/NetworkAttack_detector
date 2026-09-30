"""Direct in-process streaming fan-out for Phase 1 and Phase 2 block A."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from src.flow.flow_manager import FlowManager
from src.flow.models import DirectionalConnectionEvent, DirectionalFlowUpdate
from src.flow.snapshot_adapter import CumulativeSnapshotAdapter
from src.ingestion.zeek_websocket import FlowSnapshot, StreamEvent, TcpConnectionSignal
from src.states.common import BoundedEventDeduplicator
from src.states.ddos import DDoSStateManager
from src.states.scan import ScanStateManager


@dataclass(frozen=True, slots=True)
class CoordinatorResult:
    updates: tuple[DirectionalFlowUpdate, ...] = ()
    connection_events: tuple[DirectionalConnectionEvent, ...] = ()
    tcp_signal_accepted: bool = False


class StreamingCoordinator:
    """Fan each validated event directly to only its interested managers."""

    def __init__(
        self,
        *,
        flow_manager: FlowManager,
        adapter: CumulativeSnapshotAdapter | None = None,
        ddos_manager: DDoSStateManager | None = None,
        scan_manager: ScanStateManager | None = None,
        correlation_timeout: timedelta,
        tcp_dedup_horizon: timedelta = timedelta(minutes=10),
        tcp_dedup_max_entries: int = 100_000,
        dedup_cleanup_interval: timedelta = timedelta(seconds=5),
    ) -> None:
        if correlation_timeout <= timedelta(0):
            raise ValueError("correlation timeout must be positive")
        if dedup_cleanup_interval <= timedelta(0):
            raise ValueError("dedup cleanup interval must be positive")
        self.flow_manager = flow_manager
        self.adapter = adapter if adapter is not None else CumulativeSnapshotAdapter()
        self.ddos_manager = (
            ddos_manager if ddos_manager is not None else DDoSStateManager()
        )
        self.scan_manager = (
            scan_manager if scan_manager is not None else ScanStateManager()
        )
        self.correlation_timeout = correlation_timeout
        self.tcp_deduplicator: BoundedEventDeduplicator[
            tuple[str, str, str]
        ] = BoundedEventDeduplicator(
            horizon=tcp_dedup_horizon,
            max_entries=tcp_dedup_max_entries,
        )
        self.dedup_cleanup_interval = dedup_cleanup_interval
        self._last_dedup_cleanup_at: datetime | None = None

    def process(self, event: StreamEvent) -> CoordinatorResult:
        if isinstance(event, FlowSnapshot):
            adapted = self.adapter.adapt_with_lifecycle(event)
            for update in adapted.updates:
                self.flow_manager.update(update)
                self.ddos_manager.update_flow(update)
            for connection_event in adapted.connection_events:
                self.ddos_manager.update_connection(connection_event)
                self.scan_manager.update_connection(connection_event)
            self._cleanup(event.observed_at)
            return CoordinatorResult(adapted.updates, adapted.connection_events)

        identity = (event.zeek_uid, event.kind, event.actor_role)
        accepted = self.tcp_deduplicator.accept(identity, event.event_time)
        if accepted:
            self.ddos_manager.update_tcp(event)
            self.scan_manager.update_tcp(event)
        self._cleanup(event.event_time)
        return CoordinatorResult(tcp_signal_accepted=accepted)

    @property
    def tcp_dedup_capacity_evictions(self) -> int:
        return self.tcp_deduplicator.capacity_evictions

    def _cleanup(self, now: datetime) -> None:
        expired_flows = self.flow_manager.maybe_expire(now)
        if expired_flows is not None:
            self.adapter.expire_inactive(now, self.correlation_timeout)
        self.ddos_manager.maybe_expire(now)
        self.scan_manager.maybe_expire(now)

        if self._last_dedup_cleanup_at is None:
            self._last_dedup_cleanup_at = now
        elif (
            now >= self._last_dedup_cleanup_at
            and now - self._last_dedup_cleanup_at >= self.dedup_cleanup_interval
        ):
            self.tcp_deduplicator.expire(now)
            self._last_dedup_cleanup_at = now
