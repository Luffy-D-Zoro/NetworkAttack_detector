#!/usr/bin/env python3
"""Replay known-benign captures through the complete production alert path."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.alerts.service import AlertService
from src.calibration.manifest import load_manifest
from src.calibration.pcap import iter_zeek_pcap_events
from src.coordinator import StreamingCoordinator
from src.dns_names import dga_eligible_name
from src.flow.flow_manager import FlowManager
from src.ingestion.zeek_websocket import DNSQueryObservation

RULE_FAMILY = {
    "ddos_statistical": "ddos", "scan_statistical": "scan",
    "exfil_statistical": "exfil", "beacon_statistical": "beacon",
    "dns_statistical": "dns", "encrypted_traffic_statistical": "encrypted",
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--capture", action="append", default=[])
    args = parser.parse_args()
    report = {"dataset": load_manifest(args.manifest).name, "captures": []}
    for capture in load_manifest(args.manifest).captures:
        if args.capture and capture.capture_id not in args.capture:
            continue
        coordinator = StreamingCoordinator(
            flow_manager=FlowManager(
                inactivity_timeout=timedelta(minutes=10),
                cleanup_interval=timedelta(seconds=5),
            ),
            correlation_timeout=timedelta(minutes=15),
            alert_service=AlertService(),
        )
        evaluated: Counter[str] = Counter()
        rule_suspicious: Counter[str] = Counter()
        ml_evaluated: Counter[str] = Counter()
        ml_suspicious: Counter[str] = Counter()
        alerts: Counter[str] = Counter()
        dga_eligible = dga_rejected = events = 0
        alert_details: list[dict[str, object]] = []
        for event in iter_zeek_pcap_events(
            capture.pcap_path, policy_path=ROOT / "zeek/flow_stream.zeek"
        ):
            events += 1
            if isinstance(event, DNSQueryObservation):
                if dga_eligible_name(event.query) is None:
                    dga_rejected += 1
                else:
                    dga_eligible += 1
            result = coordinator.process(event)
            for rule in result.detector_results:
                family = RULE_FAMILY[rule.detector]
                evaluated[family] += 1
                if rule.disposition == "suspicious":
                    rule_suspicious[family] += 1
            for model in result.ml_results:
                ml_evaluated[model.family] += 1
                if model.predicted_class != "benign_like":
                    ml_suspicious[model.family] += 1
            for alert in result.alerts:
                alerts[alert.threat_family] += 1
                alert_details.append({
                    "threat_family": alert.threat_family,
                    "threat_class": alert.threat_class,
                    "subject": alert.subject,
                    "confidence": alert.confidence,
                    "evidence": list(alert.evidence),
                })
        report["captures"].append({
            "capture_id": capture.capture_id, "role": capture.role,
            "production_events": events,
            "evaluated_states_windows": dict(sorted(evaluated.items())),
            "rule_suspicious": dict(sorted(rule_suspicious.items())),
            "ml_evaluated": dict(sorted(ml_evaluated.items())),
            "ml_suspicious": dict(sorted(ml_suspicious.items())),
            "final_alerts": dict(sorted(alerts.items())),
            "final_alert_count": sum(alerts.values()),
            "alert_details": alert_details,
            "dga_queries_eligible": dga_eligible,
            "dga_queries_semantically_rejected": dga_rejected,
        })
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
