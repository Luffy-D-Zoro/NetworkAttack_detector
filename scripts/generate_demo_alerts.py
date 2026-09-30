#!/usr/bin/env python3
"""Generate controlled state/feature-driven demo alerts without network attacks."""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.alerts.service import AlertService  # noqa: E402
from src.alerts.storage import SQLiteAlertRepository  # noqa: E402
from src.detectors.rules import (  # noqa: E402
    BeaconDetector, DDoSDetector, DDoSDetectorConfig, DNSDetector, EncryptedTrafficDetector,
    EncryptedTrafficDetectorConfig, ExfilDetector, ScanDetector,
)
from src.features.extractors import DNSFeatureExtractor, EncryptedTrafficFeatureExtractor  # noqa: E402
from src.flow.models import DirectionalFlowUpdate, FlowKey  # noqa: E402
from src.ingestion.zeek_websocket import (  # noqa: E402
    DNSQueryObservation, DNSResultObservation, EncryptedProtocolObservation,
)
from src.ml.inference import MLInferenceEngine  # noqa: E402
from src.ml.training_data import generate_flow_samples  # noqa: E402
from src.states.dns import DNSStateManager  # noqa: E402
from src.states.encrypted import EncryptedStateManager  # noqa: E402


def _ip(value: str):
    return ipaddress.ip_address(value)


def _behavioral_results(engine: MLInferenceEngine, timestamp: datetime):
    detectors = {
        # The lab generator's distributed scenario is intentionally below the
        # default operational packet-rate threshold. This demo-only config
        # still requires both high rate and distributed-source evidence.
        "ddos": DDoSDetector(DDoSDetectorConfig(
            packet_rate_threshold=400.0, trigger_score=0.3,
        )), "scan": ScanDetector(),
        "exfil": ExfilDetector(), "beacon": BeaconDetector(),
    }
    samples = generate_flow_samples(seed=2404, samples_per_class=16)
    for family, detector in detectors.items():
        candidates = [row for row in samples if row.family == family and row.label != "benign_like"]
        for sample in candidates:
            feature = replace(sample.feature, timestamp=timestamp)
            rule_result = detector.detect(feature)
            ml_result = engine.infer_feature(family, feature)
            if rule_result.triggered and ml_result is not None and ml_result.predicted_class != "benign_like":
                yield rule_result, ml_result
                break
        else:
            raise RuntimeError(f"no deterministic {family} demo scenario produced matching rule/ML evidence")


def _dns_behavior(timestamp: datetime):
    manager = DNSStateManager()
    source, resolver = _ip("192.0.2.60"), _ip("198.51.100.53")
    for index in range(25):
        event_time = timestamp + timedelta(milliseconds=index * 20)
        name = f"generated{index:02d}.domain{index:02d}.com"
        manager.update_query(DNSQueryObservation(
            1, event_time, f"DEMO-DNS-{index}", source, 53_000 + index,
            resolver, 53, 17, index, name, 1, 1,
        ))
        manager.update_result(DNSResultObservation(
            1, event_time, event_time + timedelta(milliseconds=10),
            f"DEMO-DNS-{index}", source, resolver, 17, index, name,
            True, False, 3, 0.01, 0,
        ))
    state = manager.get(source)
    assert state is not None
    features = DNSFeatureExtractor(manager.config).extract(
        source, state, timestamp + timedelta(seconds=1)
    )
    return DNSDetector().detect(features)


def _dga_result(engine: MLInferenceEngine, timestamp: datetime):
    observation = DNSQueryObservation(
        1, timestamp, "DEMO-DGA", _ip("192.0.2.61"), 54_000,
        _ip("198.51.100.53"), 53, 17, 1,
        "qzx91kplm7vct2rnb4wx8j.info", 1, 1,
    )
    result = engine.infer_dga(observation)
    if result is None or result.predicted_class != "dga_like":
        raise RuntimeError("the packaged DGA model did not classify the deterministic demo domain")
    return result


def _encrypted_rule(timestamp: datetime):
    manager = EncryptedStateManager()
    client, server = _ip("192.0.2.70"), _ip("198.51.100.70")
    for index in range(6):
        event_time = timestamp + timedelta(seconds=index * 10)
        uid = f"DEMO-TLS-{index}"
        common = dict(
            schema_version=1, event_time=event_time, zeek_uid=uid,
            security_family="tls", client_ip=client, client_port=55_000 + index,
            server_ip=server, server_port=443, ip_protocol=6,
            version="SSLv3", cipher="TLS_RSA_WITH_AES_128_CBC_SHA",
            curve="secp256r1", server_name=None, alpn="http/1.1",
            resumed=False, established=False, last_alert=None,
            server_cert_fingerprint=f"sha256:demo-{index}", client_fingerprint=None,
        )
        manager.update_protocol(EncryptedProtocolObservation(kind="identified", **common))
        manager.update_protocol(EncryptedProtocolObservation(
            kind="metadata", **{**common, "last_alert": "handshake_failure"}
        ))
        key = FlowKey(client, 55_000 + index, server, 443, 6)
        manager.update_flow(DirectionalFlowUpdate(
            key, event_time, event_time + timedelta(seconds=1),
            2_000, 2_000_000, uid,
        ))
    state_key = (client, server, 443, 6, "tls")
    state = manager.get(state_key)
    assert state is not None
    features = EncryptedTrafficFeatureExtractor(manager.config).extract(
        state_key, state, timestamp + timedelta(seconds=59)
    )
    # Demo-only threshold reflects six controlled sessions in a five-minute
    # state window; metadata/outcome requirements remain unchanged.
    result = EncryptedTrafficDetector(EncryptedTrafficDetectorConfig(
        session_rate_threshold=0.003,
    )).detect(features)
    if not result.triggered:
        raise RuntimeError(
            "deterministic encrypted demo scenario did not trigger its rule: "
            f"{result.disposition}, score={result.score}, evidence={result.evidence}, "
            f"sessions={features.session_count}, rate={features.encrypted_sessions_per_second}, "
            f"byte_rates=({features.client_to_server_bytes_per_second}, "
            f"{features.server_to_client_bytes_per_second}), "
            f"active_fraction={features.repeated_service_active_time_fraction}"
        )
    return result


def generate(database: Path) -> tuple[dict[str, object], ...]:
    repository = SQLiteAlertRepository(database)
    service = AlertService(repository=repository)
    engine = MLInferenceEngine(ROOT / "models" / "phase4a")
    if len(engine.loaded_families) != 5:
        raise RuntimeError(f"required models are unavailable: {engine.disabled_models}")
    base = datetime.now(UTC).replace(microsecond=0)
    emitted = []
    try:
        for offset, (rule_result, ml_result) in enumerate(_behavioral_results(engine, base)):
            stamp = base + timedelta(seconds=offset)
            batch = service.process(
                (replace(rule_result, timestamp=stamp),),
                (replace(ml_result, timestamp=stamp),),
            )
            emitted.extend(batch.alerts)
        emitted.extend(service.process((_dns_behavior(base + timedelta(seconds=10)),), ()).alerts)
        emitted.extend(service.process((), (_dga_result(engine, base + timedelta(seconds=11)),)).alerts)
        emitted.extend(service.process((_encrypted_rule(base + timedelta(seconds=12)),), ()).alerts)
    finally:
        repository.close()
    return tuple(alert.to_dict() for alert in emitted)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--database", type=Path,
        default=ROOT / "var" / "alerts" / "alerts.db",
        help="SQLite database that will receive controlled demo alerts",
    )
    args = parser.parse_args()
    alerts = generate(args.database)
    print(json.dumps({
        "database": str(args.database), "alerts_created": len(alerts),
        "threat_classes": [item["threat_class"] for item in alerts],
        "alerts": alerts,
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
