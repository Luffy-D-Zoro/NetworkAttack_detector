"""Direct in-process streaming fan-out for current Phase 1/2 state managers."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta

from src.flow.flow_manager import FlowManager
from src.detectors.evaluator import PeriodicDetectorEvaluator
from src.detectors.models import DetectorResult
from src.flow.models import DirectionalConnectionEvent, DirectionalFlowUpdate
from src.flow.snapshot_adapter import CumulativeSnapshotAdapter
from src.ingestion.zeek_websocket import (
    DNSQueryObservation,
    DNSResultObservation,
    EncryptedProtocolObservation,
    FlowSnapshot,
    StreamEvent,
    TcpConnectionSignal,
)
from src.states.common import BoundedEventDeduplicator
from src.states.beacon import BeaconStateManager
from src.states.ddos import DDoSStateManager
from src.states.exfil import ExfilStateManager
from src.states.dns import DNSStateManager
from src.states.encrypted import EncryptedStateManager
from src.states.scan import ScanStateManager
from src.ml.inference import MLInferenceEngine
from src.ml.models import MLResult
from src.alerts.models import StructuredAlert
from src.alerts.service import AlertService


@dataclass(frozen=True, slots=True)
class CoordinatorResult:
    updates: tuple[DirectionalFlowUpdate, ...] = ()
    connection_events: tuple[DirectionalConnectionEvent, ...] = ()
    tcp_signal_accepted: bool = False
    dns_observation_accepted: bool = False
    encrypted_observation_accepted: bool = False
    encrypted_finalized: bool = False
    detector_results: tuple[DetectorResult, ...] = ()
    ml_results: tuple[MLResult, ...] = ()
    alerts: tuple[StructuredAlert, ...] = ()
    alert_persistence_failures: int = 0


class StreamingCoordinator:
    """Fan each validated event directly to only its interested managers."""

    def __init__(
        self,
        *,
        flow_manager: FlowManager,
        adapter: CumulativeSnapshotAdapter | None = None,
        ddos_manager: DDoSStateManager | None = None,
        scan_manager: ScanStateManager | None = None,
        exfil_manager: ExfilStateManager | None = None,
        beacon_manager: BeaconStateManager | None = None,
        dns_manager: DNSStateManager | None = None,
        encrypted_manager: EncryptedStateManager | None = None,
        detector_evaluator: PeriodicDetectorEvaluator | None = None,
        detector_evaluation_interval: timedelta = timedelta(seconds=10),
        ml_engine: MLInferenceEngine | None = None,
        alert_service: AlertService | None = None,
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
        self.exfil_manager = (
            exfil_manager if exfil_manager is not None else ExfilStateManager()
        )
        self.beacon_manager = (
            beacon_manager if beacon_manager is not None else BeaconStateManager()
        )
        self.dns_manager = dns_manager if dns_manager is not None else DNSStateManager()
        self.encrypted_manager = (
            encrypted_manager if encrypted_manager is not None else EncryptedStateManager()
        )
        self.ml_engine = ml_engine if ml_engine is not None else MLInferenceEngine()
        self.detector_evaluator = detector_evaluator or PeriodicDetectorEvaluator(
            ddos_manager=self.ddos_manager,
            scan_manager=self.scan_manager,
            exfil_manager=self.exfil_manager,
            beacon_manager=self.beacon_manager,
            dns_manager=self.dns_manager,
            encrypted_manager=self.encrypted_manager,
            evaluation_interval=detector_evaluation_interval,
            ml_engine=self.ml_engine,
        )
        if detector_evaluator is not None:
            self.ml_engine = detector_evaluator.ml_engine
        self.alert_service = alert_service
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
                self.exfil_manager.update_flow(update)
                self.beacon_manager.update_flow(update)
                self.encrypted_manager.update_flow(update)
            for connection_event in adapted.connection_events:
                self.ddos_manager.update_connection(connection_event)
                self.scan_manager.update_connection(connection_event)
                self.beacon_manager.update_connection(connection_event)
            encrypted_finalized = self.encrypted_manager.finalize(event)
            return self._complete(CoordinatorResult(
                updates=adapted.updates,
                connection_events=adapted.connection_events,
                encrypted_finalized=encrypted_finalized,
            ), event.observed_at)

        if isinstance(event, DNSQueryObservation):
            accepted = self.dns_manager.update_query(event)
            dga = self.ml_engine.infer_dga(event) if self.ml_engine is not None else None
            immediate = () if dga is None else (dga,)
            return self._complete(CoordinatorResult(dns_observation_accepted=accepted), event.event_time, immediate)

        if isinstance(event, DNSResultObservation):
            accepted = self.dns_manager.update_result(event)
            return self._complete(CoordinatorResult(dns_observation_accepted=accepted), event.result_time)

        if isinstance(event, EncryptedProtocolObservation):
            accepted = self.encrypted_manager.update_protocol(event)
            return self._complete(CoordinatorResult(encrypted_observation_accepted=accepted), event.event_time)

        assert isinstance(event, TcpConnectionSignal)
        identity = (event.zeek_uid, event.kind, event.actor_role)
        accepted = self.tcp_deduplicator.accept(identity, event.event_time)
        if accepted:
            self.ddos_manager.update_tcp(event)
            self.scan_manager.update_tcp(event)
        return self._complete(CoordinatorResult(tcp_signal_accepted=accepted), event.event_time)

    @property
    def tcp_dedup_capacity_evictions(self) -> int:
        return self.tcp_deduplicator.capacity_evictions

    def _complete(self, result: CoordinatorResult, now: datetime, immediate_ml: tuple[MLResult, ...] = ()) -> CoordinatorResult:
        self._cleanup(now)
        detector_results = self.detector_evaluator.maybe_evaluate(now)
        ml_results = immediate_ml + self.detector_evaluator.last_ml_results
        alert_batch = (
            self.alert_service.process(detector_results, ml_results)
            if self.alert_service is not None else None
        )
        return replace(
            result,
            detector_results=detector_results,
            ml_results=ml_results,
            alerts=alert_batch.alerts if alert_batch is not None else (),
            alert_persistence_failures=(
                alert_batch.persistence_failures if alert_batch is not None else 0
            ),
        )

    def _cleanup(self, now: datetime) -> None:
        expired_flows = self.flow_manager.maybe_expire(now)
        if expired_flows is not None:
            self.adapter.expire_inactive(now, self.correlation_timeout)
        self.ddos_manager.maybe_expire(now)
        self.scan_manager.maybe_expire(now)
        self.exfil_manager.maybe_expire(now)
        self.beacon_manager.maybe_expire(now)
        self.dns_manager.maybe_expire(now)
        self.encrypted_manager.maybe_expire(now)

        if self._last_dedup_cleanup_at is None:
            self._last_dedup_cleanup_at = now
        elif (
            now >= self._last_dedup_cleanup_at
            and now - self._last_dedup_cleanup_at >= self.dedup_cleanup_interval
        ):
            self.tcp_deduplicator.expire(now)
            self._last_dedup_cleanup_at = now
