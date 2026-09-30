from __future__ import annotations

import ipaddress
import json
import tempfile
import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

from src.alerts.fusion import AlertFusionEngine, FusionConfig, SeverityConfig
from src.alerts.models import StructuredAlert
from src.alerts.service import AlertService
from src.alerts.storage import AlertRetentionConfig, AlertStorageError, SQLiteAlertRepository
from src.alerts.suppression import AlertSuppressionConfig, AlertSuppressor
from src.coordinator import StreamingCoordinator
from src.detectors.models import DetectorResult
from src.flow.flow_manager import FlowManager
from src.ingestion.zeek_websocket import DNSQueryObservation
from src.ml.inference import MLInferenceEngine
from src.ml.models import MLResult

BASE = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)
MODELS = Path(__file__).resolve().parents[1] / "models" / "phase4a"


def rule(
    detector: str = "ddos_statistical", *, subject: str = "198.51.100.10",
    score: float = 0.9, disposition: str = "suspicious",
    evidence: tuple[str, ...] = ("signal one", "signal two"),
) -> DetectorResult:
    return DetectorResult(
        detector, subject, BASE, score, disposition == "suspicious", disposition,
        evidence, ("packets_per_second", "observed_source_entropy"),
    )


def ml(
    family: str = "ddos", *, subject: str = "198.51.100.10",
    predicted: str = "ddos_like", confidence: float = 0.9,
) -> MLResult:
    return MLResult(
        f"{family}_model", "v1", family, subject, BASE,
        predicted, confidence, {"packets_per_second": 5000.0},
    )


def alert(**changes) -> StructuredAlert:
    value = StructuredAlert(
        "alert-1", BASE, "ddos", "ddos_like", "198.51.100.10",
        0.8, "high", ("one", "two"), ("packets_per_second",),
        ("rule",), dst_ip="198.51.100.10", rule_score=0.8,
        rule_disposition="suspicious",
    )
    return replace(value, **changes)


class FusionTests(unittest.TestCase):
    def test_rule_and_ml_agreement_increases_confidence(self) -> None:
        result = AlertFusionEngine().fuse((rule(),), (ml(),))
        self.assertEqual(len(result), 1)
        self.assertAlmostEqual(result[0].confidence, 0.95)
        self.assertEqual(result[0].detection_sources, ("rule", "ml"))
        self.assertEqual(result[0].ml_score, 0.9)

    def test_rule_ml_disagreement_reduces_and_suppresses_alert(self) -> None:
        result = AlertFusionEngine().fuse(
            (rule(),), (ml(predicted="benign_like", confidence=0.9),)
        )
        self.assertEqual(result, ())

    def test_missing_ml_allows_strong_rule_alert(self) -> None:
        result = AlertFusionEngine().fuse((rule(score=0.8),), ())
        self.assertEqual(result[0].detection_sources, ("rule",))
        self.assertIsNone(result[0].ml_score)

    def test_insufficient_rule_allows_discounted_strong_ml(self) -> None:
        insufficient = rule(score=0.0, disposition="insufficient_data")
        result = AlertFusionEngine().fuse((insufficient,), (ml(confidence=0.96),))
        self.assertEqual(len(result), 1)
        self.assertAlmostEqual(result[0].confidence, 0.816)
        self.assertEqual(result[0].rule_disposition, "insufficient_data")

    def test_rule_only_encrypted_alert_has_endpoint_context(self) -> None:
        encrypted = rule(
            "encrypted_traffic_statistical",
            subject="192.0.2.1->198.51.100.20:443/6/tls", score=0.9,
        )
        result = AlertFusionEngine().fuse((encrypted,), ())
        self.assertEqual(result[0].threat_family, "encrypted_traffic")
        self.assertEqual(result[0].src_ip, "192.0.2.1")
        self.assertEqual(result[0].dst_port, 443)
        self.assertIsNone(result[0].ml_score)

    def test_dns_behavioral_and_dga_are_separate_alerts(self) -> None:
        dns = rule(
            "dns_statistical", subject="192.0.2.50", score=0.8,
            evidence=("tunneling-like long subdomains for example.test", "tunneling-like entropy"),
        )
        dga = ml(
            "dga", subject="192.0.2.50:qzx91kplm7vct2rnb4wx8j.info",
            predicted="dga_like", confidence=0.95,
        )
        dga = replace(dga, features_used={"normalized_dns_query": "qzx91kplm7vct2rnb4wx8j.info"})
        results = AlertFusionEngine().fuse((dns,), (dga,))
        self.assertEqual(len(results), 2)
        self.assertEqual({item.threat_class for item in results}, {"dns_tunneling_like", "dga_like"})
        self.assertNotEqual(results[0].subject, results[1].subject)
        self.assertTrue(all(item.src_ip == "192.0.2.50" for item in results))

    def test_dga_benign_prediction_does_not_alert(self) -> None:
        result = AlertFusionEngine().fuse(
            (), (ml("dga", subject="192.0.2.1:google.com", predicted="benign_like", confidence=0.99),)
        )
        self.assertEqual(result, ())

    def test_confidence_is_bounded_and_severity_uses_evidence(self) -> None:
        config = FusionConfig(
            agreement_bonus=0.5,
            severity=SeverityConfig(0.4, 0.6, 0.8, critical_minimum_evidence=4),
        )
        result = AlertFusionEngine(config).fuse((rule(evidence=("1", "2", "3", "4")),), (ml(confidence=1.0),))
        self.assertEqual(result[0].confidence, 1.0)
        self.assertEqual(result[0].severity, "critical")

    def test_alert_json_includes_explicit_null_fields(self) -> None:
        encoded = alert().to_json()
        value = json.loads(encoded)
        self.assertIn("src_ip", value)
        self.assertIsNone(value["src_ip"])
        self.assertEqual(value["detection_sources"], ["rule"])


class SuppressionTests(unittest.TestCase):
    def test_duplicate_is_suppressed_during_cooldown(self) -> None:
        suppressor = AlertSuppressor(AlertSuppressionConfig(cooldown=timedelta(minutes=5)))
        self.assertTrue(suppressor.accept(alert()))
        self.assertFalse(suppressor.accept(alert(alert_id="alert-2", timestamp=BASE + timedelta(seconds=10))))

    def test_increased_severity_bypasses_cooldown_and_state_is_bounded(self) -> None:
        suppressor = AlertSuppressor(AlertSuppressionConfig(max_entries=1))
        self.assertTrue(suppressor.accept(alert(confidence=0.66, severity="medium")))
        self.assertTrue(suppressor.accept(alert(alert_id="alert-2", timestamp=BASE + timedelta(seconds=10), confidence=0.82, severity="high")))
        self.assertTrue(suppressor.accept(alert(alert_id="alert-3", subject="other", timestamp=BASE + timedelta(seconds=11))))
        self.assertEqual(len(suppressor), 1)
        self.assertEqual(suppressor.capacity_evictions, 1)


class PersistenceTests(unittest.TestCase):
    def test_sqlite_insert_recent_since_filters_and_retention(self) -> None:
        repository = SQLiteAlertRepository(":memory:", AlertRetentionConfig(max_alerts=2, max_age=None))
        first = alert(alert_id="a1", confidence=0.7, severity="medium")
        second = alert(alert_id="a2", timestamp=BASE + timedelta(seconds=1), threat_family="scan", threat_class="scan_like", subject="192.0.2.1")
        third = alert(alert_id="a3", timestamp=BASE + timedelta(seconds=2), severity="critical")
        for item in (first, second, third):
            repository.insert(item)
        self.assertEqual([item.alert_id for item in repository.recent()], ["a3", "a2"])
        self.assertEqual(repository.recent(threat_family="scan")[0].alert_id, "a2")
        self.assertEqual(repository.recent(severity="critical")[0].alert_id, "a3")
        self.assertEqual(repository.alerts_since(BASE + timedelta(seconds=2))[0].alert_id, "a3")
        repository.close()

    def test_persistence_failure_does_not_drop_emitted_alert(self) -> None:
        class BrokenRepository:
            def insert(self, alert: StructuredAlert) -> None:
                raise AlertStorageError("disk unavailable")

        service = AlertService(repository=BrokenRepository())
        batch = service.process((rule(),), ())
        self.assertEqual(len(batch.alerts), 1)
        self.assertEqual(batch.persistence_failures, 1)
        self.assertEqual(service.persistence_failure_count, 1)
        self.assertIn("disk unavailable", service.last_persistence_error or "")


class RuntimeIntegrationTests(unittest.TestCase):
    def test_coordinator_emits_dga_alert_without_fusing_dns_subject(self) -> None:
        engine = MLInferenceEngine(MODELS)
        service = AlertService(
            fusion=AlertFusionEngine(FusionConfig(dga_alert_threshold=0.5)),
        )
        coordinator = StreamingCoordinator(
            flow_manager=FlowManager(
                inactivity_timeout=timedelta(seconds=120), cleanup_interval=timedelta(seconds=5)
            ),
            correlation_timeout=timedelta(seconds=300), ml_engine=engine,
            alert_service=service,
        )
        observation = DNSQueryObservation(
            1, BASE, "DGA1", ipaddress.ip_address("192.0.2.9"), 53000,
            ipaddress.ip_address("198.51.100.53"), 53, 17, 1,
            "qzx91kplm7vct2rnb4wx8j.info", 1, 1,
        )
        result = coordinator.process(observation)
        self.assertEqual(len(result.alerts), 1)
        self.assertEqual(result.alerts[0].threat_class, "dga_like")
        self.assertEqual(result.alerts[0].src_ip, "192.0.2.9")


if __name__ == "__main__":
    unittest.main()
