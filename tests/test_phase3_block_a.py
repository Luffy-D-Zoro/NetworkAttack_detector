from __future__ import annotations

import ipaddress
import unittest
from datetime import UTC, datetime, timedelta

from src.coordinator import StreamingCoordinator
from src.detectors.evaluator import PeriodicDetectorEvaluator
from src.detectors.rules import (
    BeaconDetector,
    BeaconDetectorConfig,
    DDoSDetector,
    DDoSDetectorConfig,
    ExfilDetector,
    ExfilDetectorConfig,
    ScanDetector,
    ScanDetectorConfig,
)
from src.features.extractors import (
    BeaconFeatureExtractor,
    DDoSFeatureExtractor,
    ExfilFeatureExtractor,
    ScanFeatureExtractor,
)
from src.flow.models import DirectionalConnectionEvent, DirectionalFlowUpdate, FlowKey
from src.flow.flow_manager import FlowManager
from src.ingestion.zeek_websocket import FlowSnapshot, TcpConnectionSignal
from src.states.beacon import BeaconStateConfig, BeaconStateManager
from src.states.ddos import DDoSStateConfig, DDoSStateManager
from src.states.exfil import ExfilStateConfig, ExfilStateManager
from src.states.scan import ScanStateConfig, ScanStateManager


BASE = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)


def ip(value: str):
    return ipaddress.ip_address(value)


def key(
    *,
    src: str = "192.0.2.1",
    dst: str = "198.51.100.10",
    src_port: int = 50_000,
    dst_port: int = 443,
    protocol: int = 6,
) -> FlowKey:
    return FlowKey(ip(src), src_port, ip(dst), dst_port, protocol)


def update(
    seconds: float,
    *,
    flow_key: FlowKey | None = None,
    packets: int = 1,
    ip_bytes: int = 100,
    uid: str = "C1",
) -> DirectionalFlowUpdate:
    return DirectionalFlowUpdate(
        key=flow_key or key(),
        first_seen=BASE,
        last_seen=BASE + timedelta(seconds=seconds),
        packet_delta=packets,
        byte_delta=ip_bytes,
        zeek_uid=uid,
    )


def connection(
    seconds: float,
    *,
    flow_key: FlowKey | None = None,
    kind: str = "start",
    first_seconds: float | None = None,
    packets: int = 1,
    ip_bytes: int = 100,
    uid: str = "C1",
) -> DirectionalConnectionEvent:
    first_seconds = seconds if first_seconds is None else first_seconds
    return DirectionalConnectionEvent(
        schema_version=1,
        kind=kind,
        event_time=BASE + timedelta(seconds=seconds),
        zeek_uid=uid,
        key=flow_key or key(),
        direction_role="originator",
        first_seen=BASE + timedelta(seconds=first_seconds),
        last_seen=BASE + timedelta(seconds=seconds),
        total_packets=packets,
        total_ip_bytes=ip_bytes,
    )


def tcp_signal(kind: str, seconds: float, *, uid: str, actor: str = "unknown") -> TcpConnectionSignal:
    return TcpConnectionSignal(
        schema_version=1,
        event_time=BASE + timedelta(seconds=seconds),
        zeek_uid=uid,
        kind=kind,
        orig_h=ip("192.0.2.1"),
        orig_p=50_000,
        resp_h=ip("198.51.100.10"),
        resp_p=443,
        ip_protocol=6,
        actor_role=actor,
    )


class DDoSFeatureAndDetectorTests(unittest.TestCase):
    def _config(self, *, source_capacity: int = 64) -> DDoSStateConfig:
        return DDoSStateConfig(
            window=timedelta(seconds=10),
            bucket_width=timedelta(seconds=1),
            inactivity_timeout=timedelta(seconds=20),
            cleanup_interval=timedelta(seconds=1),
            source_capacity=source_capacity,
        )

    def test_single_source_high_volume_is_not_automatically_ddos(self) -> None:
        config = self._config()
        manager = DDoSStateManager(config)
        manager.update_flow(update(9, packets=50_000, ip_bytes=50_000_000))
        state = manager.get(ip("198.51.100.10"))
        features = DDoSFeatureExtractor(config).extract(
            ip("198.51.100.10"), state, BASE + timedelta(seconds=9)  # type: ignore[arg-type]
        )
        result = DDoSDetector().detect(features)

        self.assertGreater(features.packets_per_second, 1_000)
        self.assertEqual(features.unique_observed_source_estimate, 1)
        self.assertEqual(result.disposition, "benign_like")
        self.assertFalse(result.triggered)

    def test_many_source_udp_high_rate_is_ddos_like(self) -> None:
        config = self._config()
        manager = DDoSStateManager(config)
        for number in range(20):
            manager.update_flow(
                update(
                    9,
                    flow_key=key(
                        src=f"192.0.2.{number + 1}",
                        src_port=40_000 + number,
                        protocol=17,
                    ),
                    packets=1_000,
                    ip_bytes=1_000_000,
                    uid=f"U{number}",
                )
            )
        state = manager.get(ip("198.51.100.10"))
        features = DDoSFeatureExtractor(config).extract(
            ip("198.51.100.10"), state, BASE + timedelta(seconds=9)  # type: ignore[arg-type]
        )
        detector = DDoSDetector(
            DDoSDetectorConfig(
                observed_source_threshold=10,
                minimum_source_entropy=2.0,
                packet_rate_threshold=1_000,
                byte_rate_threshold=1_000_000,
                trigger_score=0.3,
                minimum_evidence=2,
            )
        )
        result = detector.detect(features)

        self.assertEqual(features.unique_observed_source_estimate, 20)
        self.assertEqual(features.udp_packet_fraction, 1.0)
        self.assertTrue(result.triggered)
        self.assertGreaterEqual(len(result.evidence), 2)

    def test_saturated_source_cardinality_is_explicit(self) -> None:
        config = self._config(source_capacity=2)
        manager = DDoSStateManager(config)
        for number in range(5):
            manager.update_flow(
                update(
                    1,
                    flow_key=key(src=f"192.0.2.{number + 1}"),
                    uid=f"S{number}",
                )
            )
        state = manager.get(ip("198.51.100.10"))
        features = DDoSFeatureExtractor(config).extract(
            ip("198.51.100.10"), state, BASE + timedelta(seconds=1)  # type: ignore[arg-type]
        )
        result = DDoSDetector(
            DDoSDetectorConfig(minimum_packet_rate_for_evaluation=0.01)
        ).detect(features)

        self.assertTrue(features.source_cardinality_saturated)
        self.assertGreaterEqual(features.unique_observed_source_estimate, 5)
        self.assertTrue(any("saturated" in item for item in result.evidence))

    def test_connection_outcomes_reset_direction_and_acceleration_are_extracted(self) -> None:
        config = self._config()
        manager = DDoSStateManager(config)
        manager.update_flow(update(1, packets=100, ip_bytes=10_000))
        manager.update_flow(update(9, packets=400, ip_bytes=40_000, uid="C2"))
        for number in range(4):
            manager.update_tcp(tcp_signal("syn_start", 9, uid=f"T{number}"))
        manager.update_tcp(tcp_signal("established", 9, uid="TE"))
        manager.update_tcp(tcp_signal("rejected", 9, uid="TR"))
        manager.update_tcp(tcp_signal("attempt_timeout", 9, uid="TT"))
        manager.update_tcp(tcp_signal("reset", 9, uid="TS", actor="orig"))
        manager.update_tcp(tcp_signal("reset", 9, uid="TD", actor="resp"))
        state = manager.get(ip("198.51.100.10"))
        features = DDoSFeatureExtractor(config).extract(
            ip("198.51.100.10"), state, BASE + timedelta(seconds=9)  # type: ignore[arg-type]
        )

        self.assertEqual(features.establishment_ratio, 0.25)
        self.assertEqual(features.rejection_ratio, 0.25)
        self.assertEqual(features.attempt_timeout_ratio, 0.25)
        self.assertEqual(features.resets_from_source, 1)
        self.assertEqual(features.resets_from_destination, 1)
        self.assertEqual(features.recent_packet_rate_acceleration, 4.0)


class ScanFeatureAndDetectorTests(unittest.TestCase):
    def _manager(self, *, capacity: int = 64) -> ScanStateManager:
        return ScanStateManager(
            ScanStateConfig(
                window=timedelta(seconds=10),
                bucket_width=timedelta(seconds=1),
                inactivity_timeout=timedelta(seconds=20),
                cleanup_interval=timedelta(seconds=1),
                destination_ip_capacity=capacity,
                destination_port_capacity=capacity,
                destination_pair_capacity=capacity,
            )
        )

    def _features(self, manager: ScanStateManager):
        source = ip("192.0.2.1")
        return ScanFeatureExtractor(manager.config).extract(
            source, manager.get(source), BASE + timedelta(seconds=9)  # type: ignore[arg-type]
        )

    def test_horizontal_scan_and_saturation(self) -> None:
        manager = self._manager(capacity=5)
        for number in range(20):
            manager.update_connection(
                connection(
                    9,
                    flow_key=key(dst=f"198.51.100.{number + 1}"),
                    uid=f"H{number}",
                )
            )
        features = self._features(manager)
        result = ScanDetector().detect(features)

        self.assertGreaterEqual(features.unique_destination_ip_estimate, 20)
        self.assertGreaterEqual(features.horizontal_fanout_ratio or 0, 3)
        self.assertTrue(features.destination_ip_saturated)
        self.assertTrue(result.triggered)
        self.assertTrue(any("horizontal" in item for item in result.evidence))

    def test_vertical_scan(self) -> None:
        manager = self._manager()
        for number in range(20):
            manager.update_connection(
                connection(
                    9,
                    flow_key=key(dst_port=1_000 + number),
                    uid=f"V{number}",
                )
            )
        features = self._features(manager)
        result = ScanDetector().detect(features)

        self.assertEqual(features.unique_destination_ip_estimate, 1)
        self.assertEqual(features.unique_destination_port_estimate, 20)
        self.assertTrue(result.triggered)
        self.assertTrue(any("vertical" in item for item in result.evidence))

    def test_many_normal_attempts_to_one_service_are_benign_like(self) -> None:
        manager = self._manager()
        for number in range(20):
            manager.update_connection(connection(9, uid=f"N{number}"))
        result = ScanDetector().detect(self._features(manager))

        self.assertEqual(result.disposition, "benign_like")
        self.assertFalse(result.triggered)


class ExfilFeatureAndDetectorTests(unittest.TestCase):
    def _manager(self) -> ExfilStateManager:
        return ExfilStateManager(
            ExfilStateConfig(
                window=timedelta(seconds=60),
                bucket_width=timedelta(seconds=10),
                inactivity_timeout=timedelta(seconds=120),
                cleanup_interval=timedelta(seconds=5),
            )
        )

    @staticmethod
    def _detector(**overrides) -> ExfilDetector:
        values = {
            "minimum_recent_bytes": 1_000_000,
            "byte_rate_threshold": 10_000.0,
            "minimum_sustained_duration_seconds": 50.0,
            "minimum_active_time_fraction": 0.8,
            "trigger_score": 0.5,
            "minimum_evidence": 2,
        }
        values.update(overrides)
        return ExfilDetector(ExfilDetectorConfig(**values))

    def _features(self, manager: ExfilStateManager):
        state_key = (ip("192.0.2.1"), ip("198.51.100.10"))
        return ExfilFeatureExtractor(manager.config).extract(
            state_key,
            manager.get(state_key),  # type: ignore[arg-type]
            manager,
            BASE + timedelta(seconds=59),
        )

    def test_large_burst_is_not_sustained_exfiltration(self) -> None:
        manager = self._manager()
        manager.update_flow(update(1, packets=10_000, ip_bytes=20_000_000))
        features = self._features(manager)
        result = self._detector().detect(features)

        self.assertEqual(features.active_bucket_count, 1)
        self.assertEqual(result.disposition, "benign_like")
        self.assertFalse(result.triggered)

    def test_sustained_directional_transfer_with_missing_reverse_can_trigger(self) -> None:
        manager = self._manager()
        for seconds in (1, 11, 21, 31, 41, 51):
            manager.update_flow(
                update(seconds, packets=1_000, ip_bytes=1_000_000, uid=f"E{seconds}")
            )
        features = self._features(manager)
        result = self._detector().detect(features)

        self.assertEqual(features.active_bucket_count, 6)
        self.assertEqual(features.active_time_fraction, 1.0)
        self.assertFalse(features.reverse_observed)
        self.assertIsNone(features.forward_to_reverse_byte_ratio)
        self.assertTrue(result.triggered)
        self.assertTrue(any("reverse direction not observed" in item for item in result.evidence))

    def test_thresholds_are_configurable(self) -> None:
        manager = self._manager()
        for seconds in (1, 11, 21, 31, 41, 51):
            manager.update_flow(update(seconds, packets=10, ip_bytes=10_000))
        features = self._features(manager)

        strict = self._detector(minimum_recent_bytes=1_000_000).detect(features)
        permissive = self._detector(
            minimum_recent_bytes=50_000,
            byte_rate_threshold=500,
        ).detect(features)
        self.assertFalse(strict.triggered)
        self.assertTrue(permissive.triggered)

    def test_reverse_direction_ratios_are_optional_and_directional(self) -> None:
        manager = self._manager()
        manager.update_flow(update(1, packets=100, ip_bytes=10_000))
        manager.update_flow(
            update(
                1,
                flow_key=key(
                    src="198.51.100.10",
                    dst="192.0.2.1",
                    src_port=443,
                    dst_port=50_000,
                ),
                packets=10,
                ip_bytes=1_000,
                uid="reverse",
            )
        )
        features = self._features(manager)

        self.assertTrue(features.reverse_observed)
        self.assertEqual(features.forward_to_reverse_byte_ratio, 10.0)
        self.assertEqual(features.forward_to_reverse_packet_ratio, 10.0)


class BeaconFeatureAndDetectorTests(unittest.TestCase):
    def _manager(self) -> BeaconStateManager:
        return BeaconStateManager(
            BeaconStateConfig(
                horizon=timedelta(minutes=10),
                episode_gap=timedelta(seconds=2),
                inactivity_timeout=timedelta(minutes=20),
                cleanup_interval=timedelta(seconds=1),
            )
        )

    def _features(self, manager: BeaconStateManager):
        state_key = (ip("192.0.2.1"), ip("198.51.100.10"), 443, 6)
        return BeaconFeatureExtractor(manager.config).extract(
            state_key, manager.get(state_key), BASE + timedelta(seconds=100)  # type: ignore[arg-type]
        )

    def test_insufficient_samples_are_explicitly_unavailable(self) -> None:
        manager = self._manager()
        manager.update_connection(connection(0, uid="I0"))
        manager.update_connection(connection(10, uid="I1"))
        features = self._features(manager)
        result = BeaconDetector().detect(features)

        self.assertIsNone(features.connection_interarrival_variance)
        self.assertIsNone(features.connection_interarrival_coefficient_of_variation)
        self.assertEqual(result.disposition, "insufficient_data")

    def test_regular_service_contacts_alone_are_not_automatically_beaconing(self) -> None:
        manager = self._manager()
        for number, seconds in enumerate((0, 10, 20, 30, 40, 50)):
            manager.update_connection(connection(seconds, uid=f"R{number}"))
        features = self._features(manager)
        result = BeaconDetector().detect(features)

        self.assertEqual(features.connection_interarrival_coefficient_of_variation, 0.0)
        self.assertEqual(result.disposition, "benign_like")
        self.assertFalse(result.triggered)

    def test_regular_timing_and_consistent_sizes_are_beacon_like(self) -> None:
        manager = self._manager()
        for number, seconds in enumerate((0, 10, 20, 30, 40, 50)):
            flow = key(src_port=50_000 + number)
            manager.update_connection(connection(seconds, flow_key=flow, uid=f"B{number}"))
            manager.update_flow(
                update(seconds, flow_key=flow, packets=2, ip_bytes=200, uid=f"B{number}")
            )
            manager.update_connection(
                connection(
                    seconds + 1,
                    flow_key=flow,
                    kind="final",
                    first_seconds=seconds,
                    packets=2,
                    ip_bytes=200,
                    uid=f"B{number}",
                )
            )
        manager.expire(BASE + timedelta(seconds=60))
        features = self._features(manager)
        result = BeaconDetector(
            BeaconDetectorConfig(trigger_score=0.5, minimum_evidence=2)
        ).detect(features)

        self.assertEqual(features.contact_count, 6)
        self.assertGreaterEqual(features.episode_count, 4)
        self.assertEqual(features.timing_regularity, 1.0)
        self.assertEqual(features.connection_byte_variance, 0.0)
        self.assertTrue(result.triggered)


class PeriodicEvaluationTests(unittest.TestCase):
    def test_state_tables_are_evaluated_only_on_configured_cadence(self) -> None:
        ddos = DDoSStateManager()
        scan = ScanStateManager()
        exfil = ExfilStateManager()
        beacon = BeaconStateManager()
        ddos.update_flow(update(0))
        evaluator = PeriodicDetectorEvaluator(
            ddos_manager=ddos,
            scan_manager=scan,
            exfil_manager=exfil,
            beacon_manager=beacon,
            evaluation_interval=timedelta(seconds=10),
        )

        first = evaluator.maybe_evaluate(BASE)
        early = evaluator.maybe_evaluate(BASE + timedelta(seconds=9))
        due = evaluator.maybe_evaluate(BASE + timedelta(seconds=10))

        self.assertEqual(len(first), 1)
        self.assertEqual(early, ())
        self.assertEqual(len(due), 1)
        self.assertEqual(evaluator.evaluation_count, 2)

    def test_coordinator_updates_state_between_periodic_evaluations(self) -> None:
        coordinator = StreamingCoordinator(
            flow_manager=FlowManager(
                inactivity_timeout=timedelta(minutes=5),
                cleanup_interval=timedelta(seconds=5),
            ),
            correlation_timeout=timedelta(minutes=5),
            detector_evaluation_interval=timedelta(seconds=10),
        )

        def snapshot(seconds: int, packets: int) -> FlowSnapshot:
            observed = BASE + timedelta(seconds=seconds)
            return FlowSnapshot(
                schema_version=1,
                kind="open" if seconds == 0 else "update",
                observed_at=observed,
                uid="periodic-uid",
                orig_h=ip("192.0.2.1"),
                orig_p=50_000,
                resp_h=ip("198.51.100.10"),
                resp_p=443,
                ip_proto=6,
                first_seen=BASE,
                last_seen=observed,
                orig_pkts=packets,
                orig_ip_bytes=packets * 100,
                orig_payload_bytes=0,
                resp_pkts=0,
                resp_ip_bytes=0,
                resp_payload_bytes=0,
                orig_state=None,
                resp_state=None,
                history=None,
            )

        first = coordinator.process(snapshot(0, 1))
        between = coordinator.process(snapshot(5, 3))
        due = coordinator.process(snapshot(10, 4))

        destination_state = coordinator.ddos_manager.get(ip("198.51.100.10"))
        self.assertGreater(len(first.detector_results), 0)
        self.assertEqual(between.detector_results, ())
        self.assertGreater(len(due.detector_results), 0)
        self.assertEqual(sum(bucket.packets for bucket in destination_state.buckets), 4)  # type: ignore[union-attr]


if __name__ == "__main__":
    unittest.main()
