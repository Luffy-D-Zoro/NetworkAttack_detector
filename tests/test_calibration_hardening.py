from __future__ import annotations

import ipaddress
import json
import tempfile
import unittest
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

from src.alerts.fusion import AlertFusionEngine, FamilyFusionConfig, FusionConfig
from src.calibration.manifest import CaptureSpec, DatasetManifest, load_manifest
from src.calibration.metrics import binary_metrics
from src.calibration.pcap import iter_zeek_pcap_events
from src.calibration.replay import ReplayFeatureCollector
from src.calibration.training import train_behavioral_family
from src.detectors.rules import BeaconDetector, ScanDetector
from src.features.extractors import BeaconFeatureExtractor, ScanFeatureExtractor
from src.flow.models import DirectionalConnectionEvent, DirectionalFlowUpdate, FlowKey
from src.ingestion.zeek_websocket import TcpConnectionSignal
from src.ml.dga_research import _read_corpus
from src.ml.schema import raw_feature_values
from src.ml.training_data import generate_flow_samples
from src.states.beacon import BeaconStateConfig, BeaconStateManager
from src.states.scan import ScanStateConfig, ScanStateManager

BASE = datetime(2026, 9, 30, tzinfo=UTC)


def ip(value: str):
    return ipaddress.ip_address(value)


def lifecycle(key: FlowKey, seconds: float, uid: str, kind: str = "start") -> DirectionalConnectionEvent:
    first = seconds if kind == "start" else seconds - 2
    return DirectionalConnectionEvent(
        1, kind, BASE + timedelta(seconds=seconds), uid, key, "originator",
        BASE + timedelta(seconds=first), BASE + timedelta(seconds=seconds),
        3, 360,
    )


def tcp(kind: str, key: FlowKey, seconds: float, uid: str) -> TcpConnectionSignal:
    return TcpConnectionSignal(
        1, BASE + timedelta(seconds=seconds), uid, kind,
        key.src_ip, key.src_port, key.dst_ip, key.dst_port, 6, "unknown",
    )


class SemanticFalsePositiveRegressionTests(unittest.TestCase):
    def test_successful_https_cdn_fanout_is_not_a_scan(self) -> None:
        config = ScanStateConfig(window=timedelta(seconds=30), bucket_width=timedelta(seconds=1))
        manager = ScanStateManager(config)
        source = ip("10.0.0.10")
        for index in range(35):
            key = FlowKey(source, 40_000 + index, ip(f"198.51.100.{index + 1}"), 443, 6)
            uid = f"CDN{index}"
            manager.update_connection(lifecycle(key, 10 + index / 10, uid))
            manager.update_tcp(tcp("syn_start", key, 10 + index / 10, uid))
            manager.update_tcp(tcp("established", key, 10.1 + index / 10, uid))
        state = manager.get(source)
        features = ScanFeatureExtractor(config).extract(source, state, BASE + timedelta(seconds=29))  # type: ignore[arg-type]
        result = ScanDetector().detect(features)
        self.assertGreaterEqual(features.unique_destination_ip_estimate, 30)
        self.assertEqual(features.establishment_ratio, 1.0)
        self.assertEqual(result.disposition, "benign_like")
        self.assertTrue(any("successfully established" in item for item in result.evidence))

    def test_horizontal_and_vertical_scan_without_observable_replies_still_alert(self) -> None:
        for vertical in (False, True):
            config = ScanStateConfig(window=timedelta(seconds=30), bucket_width=timedelta(seconds=1))
            manager = ScanStateManager(config)
            source = ip("10.0.0.20")
            for index in range(35):
                destination = ip("198.51.100.10") if vertical else ip(f"198.51.100.{index + 1}")
                port = 1_000 + index if vertical else 443
                key = FlowKey(source, 45_000 + index, destination, port, 6)
                manager.update_connection(lifecycle(key, 10 + index / 10, f"SCAN{vertical}-{index}"))
            state = manager.get(source)
            features = ScanFeatureExtractor(config).extract(source, state, BASE + timedelta(seconds=29))  # type: ignore[arg-type]
            self.assertTrue(ScanDetector().detect(features).triggered)

    def test_repeated_cdn_fanout_without_tcp_outcomes_is_not_a_scan(self) -> None:
        config = ScanStateConfig(window=timedelta(seconds=300), bucket_width=timedelta(seconds=5))
        manager = ScanStateManager(config)
        source = ip("10.0.0.21")
        for index in range(240):
            destination_index = index % 30
            key = FlowKey(
                source, 40_000 + index, ip(f"198.51.100.{destination_index + 1}"),
                443, 6,
            )
            manager.update_connection(lifecycle(key, 10 + index / 2, f"CDNR{index}"))
        state = manager.get(source)
        features = ScanFeatureExtractor(config).extract(source, state, BASE + timedelta(seconds=299))  # type: ignore[arg-type]
        self.assertGreaterEqual(features.unique_destination_ip_estimate, 20)
        self.assertLess(features.unique_destination_pair_estimate / features.total_attempts, 0.5)
        self.assertEqual(ScanDetector().detect(features).disposition, "benign_like")

    def _beacon_result(self, destination: str, port: int):
        config = BeaconStateConfig(horizon=timedelta(hours=1), episode_gap=timedelta(seconds=8))
        manager = BeaconStateManager(config)
        source, target = ip("10.0.0.30"), ip(destination)
        for index in range(8):
            at = 5 + index * 60
            key = FlowKey(source, 50_000 + index, target, port, 17 if port in {1900, 5353} else 6)
            uid = f"BEACON{index}"
            manager.update_connection(lifecycle(key, at, uid))
            manager.update_flow(DirectionalFlowUpdate(
                key, BASE + timedelta(seconds=at), BASE + timedelta(seconds=at + 1),
                3, 360, uid,
            ))
            manager.update_connection(lifecycle(key, at + 2, uid, "final"))
        state_key = (source, target, port, 17 if port in {1900, 5353} else 6)
        state = manager.get(state_key)
        features = BeaconFeatureExtractor(config).extract(
            state_key, state, BASE + timedelta(minutes=59)  # type: ignore[arg-type]
        )
        return features, BeaconDetector().detect(features)

    def test_ssdp_multicast_periodicity_is_not_beacon_evidence(self) -> None:
        features, result = self._beacon_result("239.255.255.250", 1900)
        self.assertTrue(features.destination_is_multicast)
        self.assertEqual(result.disposition, "benign_like")

    def test_ipv6_multicast_discovery_is_not_beacon_evidence(self) -> None:
        features, result = self._beacon_result("ff02::fb", 5353)
        self.assertTrue(features.destination_is_multicast)
        self.assertEqual(result.disposition, "benign_like")

    def test_periodic_private_unicast_remains_eligible(self) -> None:
        features, result = self._beacon_result("10.0.0.50", 8443)
        self.assertFalse(features.destination_is_multicast)
        self.assertTrue(result.triggered)

    def test_regular_connection_microburst_is_not_a_beacon(self) -> None:
        config = BeaconStateConfig(horizon=timedelta(hours=1), episode_gap=timedelta(seconds=8))
        manager = BeaconStateManager(config)
        source, target = ip("10.0.0.30"), ip("198.51.100.30")
        for index in range(8):
            at = 5 + index * 0.001
            key = FlowKey(source, 50_000 + index, target, 443, 6)
            manager.update_connection(lifecycle(key, at, f"BURST{index}"))
        state_key = (source, target, 443, 6)
        features = BeaconFeatureExtractor(config).extract(
            state_key, manager.get(state_key), BASE + timedelta(minutes=59)  # type: ignore[arg-type]
        )
        self.assertLess(features.connection_interarrival_mean_seconds or 1.0, 1.0)
        self.assertEqual(BeaconDetector().detect(features).disposition, "benign_like")


class CalibrationHarnessTests(unittest.TestCase):
    def test_manifest_rejects_capture_group_leakage(self) -> None:
        capture = dict(
            dataset_name="demo", pcap_path=Path("/tmp/demo.pcap"), label="benign",
        )
        with self.assertRaisesRegex(ValueError, "multiple roles"):
            DatasetManifest(1, "demo", (
                CaptureSpec("one", role="train", split_group="same", **capture),
                CaptureSpec("two", role="test", split_group="same", **capture),
            ))

    def test_manifest_resolves_paths_and_intervals_strictly(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_text(json.dumps({
                "schema_version": 1, "name": "demo", "captures": [{
                    "capture_id": "attack", "dataset_name": "demo",
                    "pcap_path": "capture.pcap", "label": "attack",
                    "threat_family": "scan", "role": "test", "split_group": "day-1",
                    "attack_intervals": [{"start": "2026-01-01T00:00:00Z", "end": "2026-01-01T01:00:00Z"}],
                    "metadata": {"attacker_ips": ["192.0.2.1"]},
                }]
            }), encoding="utf-8")
            manifest = load_manifest(path)
            self.assertEqual(manifest.captures[0].pcap_path, Path(directory) / "capture.pcap")
            self.assertTrue(manifest.captures[0].active_label(datetime(2026, 1, 1, 0, 30, tzinfo=UTC)))

    def test_dga_families_never_cross_roles(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            corpus = Path(directory) / "dga.csv"
            lines = []
            for family in range(10):
                lines.extend(f"dga,family{family},token{family}-{index}.example\n" for index in range(3))
            lines.extend(f"legit,alexa,benign{index}.example\n" for index in range(100))
            corpus.write_text("".join(lines), encoding="utf-8")
            _, family_roles, _ = _read_corpus(corpus, 2404)
            self.assertEqual(set(family_roles.values()), {"train", "validation", "test"})
            self.assertEqual(len(family_roles), 10)

    def test_metrics_report_all_confusion_counts(self) -> None:
        result = binary_metrics([0, 0, 1, 1], [0, 1, 0, 1], [0.1, 0.8, 0.4, 0.9])
        self.assertEqual((result["tp"], result["fp"], result["tn"], result["fn"]), (1, 1, 1, 1))
        self.assertIn("pr_auc", result)

    def test_family_specific_fusion_configuration_is_immutable_and_selected(self) -> None:
        scan = FamilyFusionConfig(rule_weight=0.7, ml_weight=0.3, fused_alert_threshold=0.8)
        engine = AlertFusionEngine(FusionConfig(family_overrides=(("scan", scan),)))
        self.assertEqual(engine.config.for_family("scan"), scan)
        self.assertEqual(engine.config.for_family("ddos").rule_weight, 0.5)

    def test_behavioral_candidate_training_keeps_untouched_test_role(self) -> None:
        samples = [row for row in generate_flow_samples(seed=31, samples_per_class=12) if row.family == "scan"]
        counters = {"benign_like": 0, "scan_like": 0}
        rows = []
        for sample in samples:
            index = counters[sample.label]
            counters[sample.label] += 1
            role = "train" if index < 6 else "validation" if index < 9 else "test"
            rows.append({
                "capture_id": sample.scenario_id,
                "dataset_name": "deterministic-test",
                "split_group": sample.scenario_id,
                "role": role, "family": "scan", "label": sample.label,
                "features": raw_feature_values("scan", sample.feature),
                "rule_score": 0.8 if sample.label == "scan_like" else 0.1,
                "rule_disposition": "suspicious" if sample.label == "scan_like" else "benign_like",
            })
        with tempfile.TemporaryDirectory() as directory:
            manifest = train_behavioral_family(
                family="scan", rows=rows, output_dir=Path(directory), seed=31
            )
            self.assertEqual(manifest["sample_counts"], {"train": 12, "validation": 6, "test": 6})
            self.assertIn(manifest["algorithm"], {"logistic_regression", "random_forest", "hist_gradient_boosting"})
            self.assertEqual(manifest["test_metrics"]["samples"], 6)


@unittest.skipUnless(
    shutil.which("zeek") and Path("/usr/share/btest/data/pcaps/conn-size.trace").is_file(),
    "requires Zeek and its packaged flow fixture",
)
class CalibrationPCAPIntegrationTests(unittest.TestCase):
    def test_offline_policy_events_feed_production_features(self) -> None:
        pcap = Path("/usr/share/btest/data/pcaps/conn-size.trace")
        events = iter_zeek_pcap_events(
            pcap, policy_path=Path(__file__).resolve().parents[1] / "zeek/flow_stream.zeek"
        )
        capture = CaptureSpec(
            "zeek-fixture", "Zeek packaged test fixture", pcap,
            "benign", "test", "zeek-fixture-capture",
        )
        rows = ReplayFeatureCollector().collect(events, capture)
        self.assertTrue(rows)
        self.assertTrue({"ddos", "scan", "exfil", "beacon"}.issubset({row.family for row in rows}))


if __name__ == "__main__":
    unittest.main()
