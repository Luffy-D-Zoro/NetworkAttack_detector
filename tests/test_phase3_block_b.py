from __future__ import annotations

import ipaddress
import unittest
from datetime import UTC, datetime, timedelta

from src.coordinator import StreamingCoordinator
from src.detectors.rules import (
    DNSDetector,
    DNSDetectorConfig,
    EncryptedTrafficDetector,
    EncryptedTrafficDetectorConfig,
)
from src.features.extractors import DNSFeatureExtractor, EncryptedTrafficFeatureExtractor
from src.flow.flow_manager import FlowManager
from src.flow.models import DirectionalFlowUpdate, FlowKey
from src.ingestion.zeek_websocket import (
    DNSQueryObservation,
    DNSResultObservation,
    EncryptedProtocolObservation,
    FlowSnapshot,
)
from src.states.dns import DNSStateConfig, DNSStateManager
from src.states.encrypted import EncryptedStateConfig, EncryptedStateManager


BASE = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)


def ip(value: str):
    return ipaddress.ip_address(value)


def dns_query(
    index: int,
    name: str,
    *,
    source: str = "192.0.2.1",
    qtype: int = 1,
    qclass: int = 1,
) -> DNSQueryObservation:
    return DNSQueryObservation(
        1,
        BASE + timedelta(seconds=index / 10),
        f"D{index}",
        ip(source),
        53_000 + index,
        ip("198.51.100.53"),
        53,
        17,
        index,
        name,
        qtype,
        qclass,
    )


def dns_result(
    index: int,
    name: str,
    *,
    source: str = "192.0.2.1",
    saw_reply: bool = True,
    rejected: bool = False,
    rcode: int | None = 0,
    rtt: float | None = 0.02,
    answers: int | None = 1,
) -> DNSResultObservation:
    query_time = BASE + timedelta(seconds=index / 10)
    return DNSResultObservation(
        1,
        query_time,
        query_time + timedelta(milliseconds=20),
        f"D{index}",
        ip(source),
        ip("198.51.100.53"),
        17,
        index,
        name,
        saw_reply,
        rejected,
        rcode,
        rtt,
        answers,
    )


def encrypted_observation(
    index: int,
    *,
    kind: str = "identified",
    version: str | None = "TLSv13",
    cipher: str | None = "TLS_AES_128_GCM_SHA256",
    curve: str | None = "x25519",
    sni: str | None = "service.example",
    alpn: str | None = "h2",
    resumed: bool | None = False,
    established: bool | None = True,
    alert: str | None = None,
    certificate: str | None = "sha256:stable",
    family: str = "tls",
) -> EncryptedProtocolObservation:
    protocol = 17 if family in {"dtls", "quic"} else 6
    return EncryptedProtocolObservation(
        1,
        kind,
        BASE + timedelta(seconds=index * 10),
        f"E{index}",
        family,
        ip("192.0.2.10"),
        50_000 + index,
        ip("198.51.100.20"),
        443,
        protocol,
        version,
        cipher if family != "quic" else None,
        curve if family != "quic" else None,
        sni,
        alpn,
        resumed if family != "quic" else None,
        established,
        alert,
        certificate if family != "quic" else None,
        None,
    )


def encrypted_update(
    index: int,
    *,
    reverse: bool = False,
    packets: int = 10,
    size: int = 10_000,
) -> DirectionalFlowUpdate:
    if reverse:
        flow_key = FlowKey(
            ip("198.51.100.20"), 443, ip("192.0.2.10"), 50_000 + index, 6
        )
    else:
        flow_key = FlowKey(
            ip("192.0.2.10"), 50_000 + index, ip("198.51.100.20"), 443, 6
        )
    return DirectionalFlowUpdate(
        flow_key,
        BASE + timedelta(seconds=index * 10),
        BASE + timedelta(seconds=index * 10 + 1),
        packets,
        size,
        f"E{index}",
    )


def encrypted_final(
    index: int,
    *,
    packets: int = 10,
    size: int = 10_000,
    reverse_packets: int = 5,
    reverse_size: int = 5_000,
) -> FlowSnapshot:
    first = BASE + timedelta(seconds=index * 10)
    observed = first + timedelta(seconds=2)
    return FlowSnapshot(
        1,
        "final",
        observed,
        f"E{index}",
        ip("192.0.2.10"),
        50_000 + index,
        ip("198.51.100.20"),
        443,
        6,
        first,
        first + timedelta(seconds=1),
        packets,
        size,
        0,
        reverse_packets,
        reverse_size,
        0,
        1,
        1,
        "ShAD",
    )


class DNSFeatureAndDetectorTests(unittest.TestCase):
    def manager(self, **changes: object) -> DNSStateManager:
        values = dict(
            source_window=timedelta(seconds=20),
            source_bucket_width=timedelta(seconds=5),
            domain_window=timedelta(seconds=30),
            domain_bucket_width=timedelta(seconds=5),
            inactivity_timeout=timedelta(seconds=60),
            domain_inactivity_timeout=timedelta(seconds=60),
            cleanup_interval=timedelta(seconds=1),
            max_state_entries=10,
            domain_capacity=64,
            category_capacity=64,
            qname_hash_capacity=128,
            domain_hash_capacity=128,
            subdomain_hash_capacity=128,
            dedup_horizon=timedelta(seconds=30),
            dedup_max_entries=1_000,
        )
        values.update(changes)
        return DNSStateManager(DNSStateConfig(**values))

    def features(self, manager: DNSStateManager):
        source = ip("192.0.2.1")
        return DNSFeatureExtractor(manager.config).extract(
            source, manager.get(source), BASE + timedelta(seconds=19)  # type: ignore[arg-type]
        )

    def test_benign_repeated_dns_and_response_statistics(self) -> None:
        manager = self.manager()
        for index in range(10):
            name = "www.example.com"
            manager.update_query(dns_query(index, name))
            manager.update_result(dns_result(index, name, answers=2))
        features = self.features(manager)
        result = DNSDetector().detect(features)

        self.assertEqual(features.unique_qname_estimate, 1)
        self.assertEqual(features.unique_registrable_domain_estimate, 1)
        self.assertEqual(features.nxdomain_ratio, 0.0)
        self.assertEqual(features.mean_answer_count_per_reply, 2.0)
        self.assertEqual(result.disposition, "benign_like")

    def test_tunneling_like_pattern_requires_multiple_domain_indicators(self) -> None:
        manager = self.manager()
        for index in range(20):
            subdomain = f"a{index:02x}b3c4d5e6f708192a3b4c5d6e7f8{index:02x}"
            manager.update_query(
                dns_query(index, f"{subdomain}.tunnel.example.com", qtype=16)
            )
        features = self.features(manager)
        result = DNSDetector().detect(features)
        domain = features.domain_features["example.com"]

        self.assertGreater(domain.mean_subdomain_length or 0, 25)
        self.assertGreater(domain.mean_subdomain_entropy or 0, 3.5)
        self.assertEqual(domain.repetition_ratio, 0.0)
        self.assertTrue(result.triggered)
        self.assertTrue(any("tunneling-like" in item for item in result.evidence))

    def test_high_entropy_alone_is_not_dns_tunneling(self) -> None:
        manager = self.manager()
        for index in range(10):
            manager.update_query(
                dns_query(index, "a1b2c3d4e5f60718.normal.example")
            )
        result = DNSDetector().detect(self.features(manager))
        self.assertFalse(result.triggered)

    def test_dga_like_fanout_and_nxdomain_combination(self) -> None:
        manager = self.manager()
        for index in range(20):
            name = f"generated{index:02d}.domain{index:02d}.com"
            manager.update_query(dns_query(index, name))
            manager.update_result(dns_result(index, name, rcode=3, answers=0))
        features = self.features(manager)
        result = DNSDetector().detect(features)

        self.assertEqual(features.unique_registrable_domain_estimate, 20)
        self.assertEqual(features.nxdomain_ratio, 1.0)
        self.assertTrue(result.triggered)
        self.assertTrue(any("DGA-like" in item for item in result.evidence))

    def test_high_rate_failed_queries_form_abnormal_dns_evidence(self) -> None:
        manager = self.manager(
            qname_hash_capacity=256,
            dedup_max_entries=2_000,
        )
        for index in range(100):
            name = "service.example.com"
            manager.update_query(dns_query(index, name))
            manager.update_result(
                dns_result(
                    index,
                    name,
                    saw_reply=False,
                    rejected=True,
                    rcode=None,
                    rtt=None,
                    answers=None,
                )
            )
        features = self.features(manager)
        result = DNSDetector().detect(features)

        self.assertEqual(features.no_reply_ratio, 1.0)
        self.assertEqual(features.rejection_ratio, 1.0)
        self.assertTrue(result.triggered)
        self.assertTrue(any("abnormal" in item for item in result.evidence))

    def test_missing_responses_remain_unavailable(self) -> None:
        manager = self.manager()
        for index in range(10):
            manager.update_query(dns_query(index, "www.example.com"))
        features = self.features(manager)

        self.assertEqual(features.result_count, 0)
        self.assertIsNone(features.nxdomain_ratio)
        self.assertIsNone(features.no_reply_ratio)
        self.assertIsNone(features.mean_rtt_seconds)
        self.assertIsNone(features.answer_count_total)

    def test_saturation_and_threshold_configuration(self) -> None:
        manager = self.manager(
            domain_capacity=1,
            qname_hash_capacity=2,
            domain_hash_capacity=2,
            subdomain_hash_capacity=2,
        )
        for index in range(6):
            manager.update_query(
                dns_query(index, f"unique{index}.domain{index}.com")
            )
        features = self.features(manager)
        permissive = DNSDetector(
            DNSDetectorConfig(
                minimum_queries=1,
                dga_unique_domain_threshold=3,
                dga_domain_fanout_per_second=0.1,
                dga_unique_qname_ratio=0.5,
                dga_minimum_indicators=3,
                trigger_score=0.5,
            )
        ).detect(features)
        strict = DNSDetector(
            DNSDetectorConfig(
                minimum_queries=1,
                dga_unique_domain_threshold=100,
                dga_domain_fanout_per_second=100.0,
                dga_minimum_indicators=5,
            )
        ).detect(features)

        self.assertTrue(features.qname_cardinality_saturated)
        self.assertTrue(features.registrable_domain_cardinality_saturated)
        self.assertTrue(features.domain_map_saturated)
        self.assertTrue(permissive.triggered)
        self.assertFalse(strict.triggered)
        self.assertTrue(any("saturated" in item for item in permissive.evidence))

    def test_insufficient_dns_data(self) -> None:
        manager = self.manager()
        manager.update_query(dns_query(0, "one.example"))
        result = DNSDetector().detect(self.features(manager))
        self.assertEqual(result.disposition, "insufficient_data")


class EncryptedFeatureAndDetectorTests(unittest.TestCase):
    def manager(self, **changes: object) -> EncryptedStateManager:
        values = dict(
            window=timedelta(seconds=60),
            bucket_width=timedelta(seconds=10),
            completed_horizon=timedelta(seconds=120),
            completed_sample_capacity=32,
            session_timeout=timedelta(seconds=90),
            inactivity_timeout=timedelta(seconds=180),
            cleanup_interval=timedelta(seconds=1),
            max_state_entries=10,
            sessions_per_state=32,
            uid_capacity=100,
            category_capacity=32,
            final_dedup_horizon=timedelta(seconds=90),
            final_dedup_capacity=100,
            category_length_limit=64,
        )
        values.update(changes)
        return EncryptedStateManager(EncryptedStateConfig(**values))

    @staticmethod
    def state_key(family: str = "tls"):
        return (
            ip("192.0.2.10"),
            ip("198.51.100.20"),
            443,
            17 if family in {"dtls", "quic"} else 6,
            family,
        )

    def features(self, manager: EncryptedStateManager, family: str = "tls"):
        state_key = self.state_key(family)
        return EncryptedTrafficFeatureExtractor(manager.config).extract(
            state_key,
            manager.get(state_key),  # type: ignore[arg-type]
            BASE + timedelta(seconds=59),
        )

    def add_normal_session(self, manager: EncryptedStateManager, index: int) -> None:
        manager.update_protocol(encrypted_observation(index))
        manager.update_protocol(encrypted_observation(index, kind="metadata"))
        manager.update_flow(encrypted_update(index))
        manager.update_flow(encrypted_update(index, reverse=True, packets=5, size=5_000))
        manager.finalize(encrypted_final(index))

    def test_benign_encrypted_service_and_session_statistics(self) -> None:
        manager = self.manager()
        for index in range(6):
            self.add_normal_session(manager, index)
        features = self.features(manager)
        result = EncryptedTrafficDetector().detect(features)

        self.assertEqual(features.security_family, "tls")
        self.assertEqual(features.session_count, 6)
        self.assertTrue(features.client_to_server_observed)
        self.assertTrue(features.server_to_client_observed)
        self.assertEqual(features.client_to_server_byte_ratio, 2.0)
        self.assertEqual(features.mean_session_duration_seconds, 1.0)
        self.assertEqual(features.establishment_ratio, 1.0)
        self.assertEqual(features.missing_sni_ratio, 0.0)
        self.assertEqual(result.disposition, "benign_like")

    def test_behavior_and_protocol_outcomes_combine_as_suspicious(self) -> None:
        manager = self.manager()
        for index in range(6):
            manager.update_protocol(
                encrypted_observation(index, sni=None, established=False)
            )
            manager.update_protocol(
                encrypted_observation(
                    index,
                    kind="metadata",
                    sni=None,
                    established=False,
                    alert="handshake_failure",
                )
            )
            manager.update_flow(encrypted_update(index, packets=20, size=20_000))
        features = self.features(manager)
        result = EncryptedTrafficDetector().detect(features)

        self.assertFalse(features.server_to_client_observed)
        self.assertIsNone(features.client_to_server_byte_ratio)
        self.assertEqual(features.incomplete_ratio, 1.0)
        self.assertEqual(features.alert_ratio, 1.0)
        self.assertEqual(features.missing_sni_ratio, 1.0)
        self.assertTrue(result.triggered)

    def test_encryption_or_missing_direction_alone_is_not_suspicious(self) -> None:
        manager = self.manager()
        for index in range(6):
            manager.update_protocol(encrypted_observation(index))
            manager.update_protocol(encrypted_observation(index, kind="metadata"))
            manager.update_flow(encrypted_update(index))
        features = self.features(manager)
        result = EncryptedTrafficDetector().detect(features)

        self.assertFalse(features.server_to_client_observed)
        self.assertIsNone(features.client_to_server_packet_ratio)
        self.assertFalse(result.triggered)

    def test_quic_family_keeps_unavailable_metadata_none(self) -> None:
        manager = self.manager()
        for index in range(6):
            manager.update_protocol(
                encrypted_observation(index, family="quic", version="1")
            )
        features = self.features(manager, "quic")

        self.assertEqual(features.security_family, "quic")
        self.assertIsNone(features.cipher_distribution)
        self.assertIsNone(features.curve_distribution)
        self.assertIsNone(features.resumption_ratio)
        self.assertIsNone(features.certificate_fingerprint_distribution)

    def test_category_saturation_and_configurable_thresholds(self) -> None:
        manager = self.manager(
            category_capacity=2, bucket_width=timedelta(seconds=60)
        )
        for index in range(6):
            manager.update_protocol(
                encrypted_observation(
                    index,
                    version=f"legacy-{index}",
                    sni=f"host{index}.example",
                    certificate=f"sha256:{index}",
                    established=False,
                )
            )
            manager.update_protocol(
                encrypted_observation(
                    index,
                    kind="metadata",
                    version=f"legacy-{index}",
                    sni=f"host{index}.example",
                    certificate=f"sha256:{index}",
                    established=False,
                    alert="failure",
                )
            )
        features = self.features(manager)
        permissive = EncryptedTrafficDetector(
            EncryptedTrafficDetectorConfig(
                minimum_sessions=1,
                session_rate_threshold=0.01,
                minimum_metadata_outcome_indicators=2,
                minimum_total_indicators=3,
                trigger_score=0.3,
            )
        ).detect(features)
        strict = EncryptedTrafficDetector(
            EncryptedTrafficDetectorConfig(
                minimum_sessions=1,
                session_rate_threshold=100.0,
                minimum_behavioral_indicators=4,
                minimum_metadata_outcome_indicators=5,
                minimum_total_indicators=9,
            )
        ).detect(features)

        self.assertTrue(features.categorical_saturated)
        self.assertTrue(features.sni_cardinality_saturated)
        self.assertTrue(features.certificate_cardinality_saturated)
        self.assertTrue(permissive.triggered)
        self.assertFalse(strict.triggered)
        self.assertTrue(any("saturated" in item for item in permissive.evidence))

    def test_insufficient_encrypted_sessions(self) -> None:
        manager = self.manager()
        manager.update_protocol(encrypted_observation(0))
        result = EncryptedTrafficDetector().detect(self.features(manager))
        self.assertEqual(result.disposition, "insufficient_data")


class PeriodicBlockBEvaluationTests(unittest.TestCase):
    def test_coordinator_periodically_evaluates_dns_and_encrypted_state(self) -> None:
        coordinator = StreamingCoordinator(
            flow_manager=FlowManager(
                inactivity_timeout=timedelta(minutes=5),
                cleanup_interval=timedelta(seconds=1),
            ),
            correlation_timeout=timedelta(minutes=5),
            detector_evaluation_interval=timedelta(seconds=10),
        )
        first = coordinator.process(dns_query(0, "www.example.com"))
        due = coordinator.process(encrypted_observation(1))

        self.assertIn("dns_statistical", {item.detector for item in first.detector_results})
        self.assertIn(
            "encrypted_traffic_statistical",
            {item.detector for item in due.detector_results},
        )


if __name__ == "__main__":
    unittest.main()
