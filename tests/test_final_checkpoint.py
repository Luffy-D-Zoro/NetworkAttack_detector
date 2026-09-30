from __future__ import annotations

import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from scripts.benchmark_pipeline import run as run_benchmark
from scripts.generate_demo_alerts import generate
from src.alerts.storage import AlertStorageError, SQLiteAlertRepository
from src.dashboard_data import load_dashboard_snapshot


class FinalCheckpointTests(unittest.TestCase):
    def test_controlled_demo_persists_all_supported_alert_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "alerts.db"
            alerts = generate(database)
            self.assertEqual(len(alerts), 7)
            self.assertEqual(
                {alert["threat_family"] for alert in alerts},
                {"ddos", "scan", "exfiltration", "beaconing", "dns", "encrypted_traffic"},
            )

            repository = SQLiteAlertRepository(database, read_only=True)
            try:
                self.assertEqual(repository.count(), 7)
                self.assertEqual(repository.counts_by("threat_family")["dns"], 2)
                with self.assertRaises(AlertStorageError):
                    repository.insert(repository.recent(1)[0])
            finally:
                repository.close()

            snapshot = load_dashboard_snapshot(
                database, recent_window=timedelta(hours=1),
                now=datetime.now(UTC) + timedelta(minutes=1),
            )
            self.assertEqual(snapshot.total_alerts, 7)
            self.assertEqual(snapshot.recent_alert_count, 7)
            self.assertEqual(len(snapshot.alerts), 7)
            self.assertIsNotNone(snapshot.latest_alert_timestamp)

    def test_dashboard_does_not_create_a_missing_database(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "missing.db"
            with self.assertRaises(AlertStorageError):
                load_dashboard_snapshot(database)
            self.assertFalse(database.exists())

    def test_benchmark_smoke_exercises_all_reported_stages(self) -> None:
        result = run_benchmark(100, 2)
        self.assertFalse(result["scope"]["zeek_capture_included"])
        self.assertEqual(
            set(result["results"]),
            {
                "strict_json_ingestion", "state_fanout", "full_coordinator",
                "rule_detector_evaluation", "ml_inference",
            },
        )
        for stage in result["results"].values():
            self.assertGreater(stage["throughput_per_second"], 0)
            self.assertGreaterEqual(stage["latency"]["p95_us"], 0)


if __name__ == "__main__":
    unittest.main()
