from __future__ import annotations

import ipaddress
import json
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from src.detectors.evaluator import PeriodicDetectorEvaluator
from src.features.extractors import DDoSFeatureExtractor
from src.flow.models import DirectionalFlowUpdate, FlowKey
from src.ingestion.zeek_websocket import DNSQueryObservation
from src.ml.inference import MLInferenceEngine
from src.ml.schema import FAMILY_FEATURES, expanded_feature_names, raw_feature_values
from src.ml.training import train_all
from src.ml.training_data import generate_flow_samples
from src.states.beacon import BeaconStateManager
from src.states.ddos import DDoSStateConfig, DDoSStateManager
from src.states.exfil import ExfilStateManager
from src.states.scan import ScanStateManager

BASE = datetime(2026, 1, 1, tzinfo=UTC)
ARTIFACTS = Path(__file__).resolve().parents[1] / "models" / "phase4a"


class Phase4ATrainingTests(unittest.TestCase):
    def test_scenario_generation_is_deterministic_and_balanced(self) -> None:
        first = generate_flow_samples(seed=19, samples_per_class=3)
        second = generate_flow_samples(seed=19, samples_per_class=3)
        self.assertEqual(
            [(row.family, row.label, raw_feature_values(row.family, row.feature)) for row in first],
            [(row.family, row.label, raw_feature_values(row.family, row.feature)) for row in second],
        )
        self.assertEqual(len(first), 24)

    def test_schema_order_is_exact_and_has_availability_columns(self) -> None:
        for family, names in FAMILY_FEATURES.items():
            expanded = expanded_feature_names(family)
            self.assertEqual(len(expanded), len(names) * 2)
            self.assertEqual(expanded[:2], (names[0], f"{names[0]}__available"))

    def test_training_saves_loadable_artifacts_and_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            summary = train_all(
                output_dir=root / "models", data_dir=root / "data", seed=7,
                flow_samples_per_class=10, dga_samples_per_class=40,
            )
            engine = MLInferenceEngine(root / "models")
            self.assertEqual(set(engine.loaded_families), {"ddos", "scan", "exfil", "beacon", "dga"})
            self.assertEqual(summary["flow_samples"], 80)
            self.assertTrue((root / "data" / "flow_scenarios.jsonl").is_file())
            self.assertTrue((root / "data" / "dga_domains.csv").is_file())
            self.assertTrue((root / "models" / "validation_metrics.json").is_file())

    def test_schema_mismatch_disables_only_that_model(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            train_all(output_dir=root / "models", data_dir=root / "data", flow_samples_per_class=8, dga_samples_per_class=30)
            manifest_path = root / "models" / "ddos.manifest.json"
            manifest = json.loads(manifest_path.read_text())
            manifest["raw_feature_names"].reverse()
            manifest_path.write_text(json.dumps(manifest))
            engine = MLInferenceEngine(root / "models")
            self.assertNotIn("ddos", engine.loaded_families)
            self.assertIn("ddos", engine.disabled_models)
            self.assertIn("scan", engine.loaded_families)

    def test_missing_models_degrade_gracefully(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            engine = MLInferenceEngine(Path(temporary))
            self.assertEqual(engine.loaded_families, ())
            self.assertEqual(set(engine.disabled_models), {"ddos", "scan", "exfil", "beacon", "dga"})


class Phase4AInferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.engine = MLInferenceEngine(ARTIFACTS)

    def test_flow_models_separate_obvious_generated_scenarios(self) -> None:
        samples = generate_flow_samples(seed=2404, samples_per_class=4)
        for family in FAMILY_FEATURES:
            benign = next(row for row in samples if row.family == family and row.label == "benign_like")
            suspicious = next(row for row in samples if row.family == family and row.label != "benign_like")
            benign_result = self.engine.infer_feature(family, benign.feature)
            suspicious_result = self.engine.infer_feature(family, suspicious.feature)
            self.assertIsNotNone(benign_result)
            self.assertIsNotNone(suspicious_result)
            self.assertEqual(benign_result.predicted_class, "benign_like")  # type: ignore[union-attr]
            self.assertEqual(suspicious_result.predicted_class, f"{family}_like")  # type: ignore[union-attr]
            self.assertLessEqual(suspicious_result.confidence, 1.0)  # type: ignore[union-attr]
            self.assertGreaterEqual(suspicious_result.confidence, 0.0)  # type: ignore[union-attr]

    def _dns(self, query: str) -> DNSQueryObservation:
        return DNSQueryObservation(
            1, BASE, "DNS1", ipaddress.ip_address("192.0.2.1"), 53000,
            ipaddress.ip_address("198.51.100.53"), 53, 17, 1, query, 1, 1,
        )

    def test_dga_training_and_inference(self) -> None:
        benign = self.engine.infer_dga(self._dns("WWW.Google.COM."))
        suspicious = self.engine.infer_dga(self._dns("qzx91kplm7vct2rnb4wx8j.info"))
        self.assertEqual(benign.predicted_class, "benign_like")  # type: ignore[union-attr]
        self.assertEqual(benign.features_used["normalized_dns_query"], "www.google.com")  # type: ignore[union-attr]
        self.assertEqual(suspicious.predicted_class, "dga_like")  # type: ignore[union-attr]
        self.assertTrue(0.0 <= suspicious.confidence <= 1.0)  # type: ignore[union-attr]

    def test_dga_semantic_eligibility_precedes_inference(self) -> None:
        for query in (
            "sumitr", "printer", "randomsinglelabelxyz", "host.local",
            "1.0.0.127.in-addr.arpa", "b.a.9.8.7.6.5.0.4.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa",
            "127.0.0.1", "2001:db8::1", "localhost",
        ):
            with self.subTest(query=query):
                self.assertIsNone(self.engine.infer_dga(self._dns(query)))

        normal = self.engine.infer_dga(self._dns("www.google.com"))
        dga = self.engine.infer_dga(self._dns("qzx91kplm7vct2rnb4wx8j.info"))
        self.assertIsNotNone(normal)
        self.assertEqual(dga.predicted_class, "dga_like")  # type: ignore[union-attr]

    def test_periodic_evaluator_runs_ml_only_on_cadence(self) -> None:
        config = DDoSStateConfig(window=timedelta(seconds=60), bucket_width=timedelta(seconds=5))
        ddos = DDoSStateManager(config)
        destination = ipaddress.ip_address("198.51.100.1")
        for index in range(30):
            key = FlowKey(ipaddress.ip_address(f"10.0.0.{index + 1}"), 40000 + index, destination, 53, 17)
            ddos.update_flow(DirectionalFlowUpdate(key, BASE, BASE + timedelta(seconds=5), 500, 500_000, f"U{index}"))
        evaluator = PeriodicDetectorEvaluator(
            ddos_manager=ddos, scan_manager=ScanStateManager(),
            exfil_manager=ExfilStateManager(), beacon_manager=BeaconStateManager(),
            evaluation_interval=timedelta(seconds=10), ml_engine=self.engine,
        )
        evaluator.maybe_evaluate(BASE + timedelta(seconds=6))
        self.assertEqual(len(evaluator.last_ml_results), 1)
        self.assertEqual(evaluator.last_ml_results[0].family, "ddos")
        evaluator.maybe_evaluate(BASE + timedelta(seconds=7))
        self.assertEqual(evaluator.last_ml_results, ())


if __name__ == "__main__":
    unittest.main()
