"""Extract labelled windows from replayed Zeek events using production code."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, fields
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable

from src.calibration.manifest import CaptureSpec
from src.coordinator import StreamingCoordinator
from src.detectors.evaluator import PeriodicDetectorEvaluator
from src.detectors.rules import (
    BeaconDetector, DDoSDetector, DNSDetector, EncryptedTrafficDetector,
    ExfilDetector, ScanDetector,
)
from src.features.extractors import (
    BeaconFeatureExtractor, DDoSFeatureExtractor, DNSFeatureExtractor,
    EncryptedTrafficFeatureExtractor, ExfilFeatureExtractor, ScanFeatureExtractor,
)
from src.flow.flow_manager import FlowManager
from src.ingestion.zeek_websocket import (
    DNSQueryObservation, DNSResultObservation, EncryptedProtocolObservation,
    FlowSnapshot, StreamEvent, TcpConnectionSignal,
)
from src.ml.schema import raw_feature_values, schema_manifest
from src.states.beacon import BeaconStateManager
from src.states.ddos import DDoSStateManager
from src.states.dns import DNSStateManager
from src.states.encrypted import EncryptedStateManager
from src.states.exfil import ExfilStateManager
from src.states.scan import ScanStateManager


@dataclass(frozen=True, slots=True)
class FeatureRow:
    capture_id: str
    dataset_name: str
    split_group: str
    role: str
    family: str
    label: str
    timestamp: datetime
    subject: str
    features: dict[str, object]
    rule_score: float
    rule_disposition: str

    def to_dict(self) -> dict[str, object]:
        value = asdict(self)
        value["timestamp"] = self.timestamp.isoformat().replace("+00:00", "Z")
        return value


def event_time(event: StreamEvent) -> datetime:
    if isinstance(event, FlowSnapshot):
        return event.observed_at
    if isinstance(event, DNSResultObservation):
        return event.result_time
    if isinstance(event, (DNSQueryObservation, EncryptedProtocolObservation, TcpConnectionSignal)):
        return event.event_time
    raise TypeError(f"unsupported stream event {type(event).__name__}")


class ReplayFeatureCollector:
    """Periodic sampler over the exact runtime managers/extractors.

    Sampling scans bounded state tables only at the configured cadence, just as
    the production evaluator does.  It never derives substitute CSV features.
    """

    def __init__(self, *, interval: timedelta = timedelta(seconds=10)) -> None:
        if interval <= timedelta(0):
            raise ValueError("sampling interval must be positive")
        self.interval = interval
        self.ddos = DDoSStateManager()
        self.scan = ScanStateManager()
        self.exfil = ExfilStateManager()
        self.beacon = BeaconStateManager()
        self.dns = DNSStateManager()
        self.encrypted = EncryptedStateManager()
        evaluator = PeriodicDetectorEvaluator(
            ddos_manager=self.ddos, scan_manager=self.scan,
            exfil_manager=self.exfil, beacon_manager=self.beacon,
            dns_manager=self.dns, encrypted_manager=self.encrypted,
            evaluation_interval=timedelta(days=36500), ml_engine=None,
        )
        self.coordinator = StreamingCoordinator(
            flow_manager=FlowManager(
                inactivity_timeout=timedelta(minutes=10),
                cleanup_interval=timedelta(seconds=5),
            ),
            ddos_manager=self.ddos, scan_manager=self.scan,
            exfil_manager=self.exfil, beacon_manager=self.beacon,
            dns_manager=self.dns, encrypted_manager=self.encrypted,
            detector_evaluator=evaluator,
            correlation_timeout=timedelta(minutes=15),
        )
        self.extractors = {
            "ddos": DDoSFeatureExtractor(self.ddos.config),
            "scan": ScanFeatureExtractor(self.scan.config),
            "exfil": ExfilFeatureExtractor(self.exfil.config),
            "beacon": BeaconFeatureExtractor(self.beacon.config),
            "dns": DNSFeatureExtractor(self.dns.config),
            "encrypted": EncryptedTrafficFeatureExtractor(self.encrypted.config),
        }
        self.detectors = {
            "ddos": DDoSDetector(), "scan": ScanDetector(),
            "exfil": ExfilDetector(), "beacon": BeaconDetector(),
            "dns": DNSDetector(), "encrypted": EncryptedTrafficDetector(),
        }

    def collect(self, events: Iterable[StreamEvent], capture: CaptureSpec) -> tuple[FeatureRow, ...]:
        return tuple(self.iter_collect(events, capture))

    def iter_collect(self, events: Iterable[StreamEvent], capture: CaptureSpec) -> Iterable[FeatureRow]:
        next_sample: datetime | None = None
        last_seen: datetime | None = None
        last_sampled: datetime | None = None
        for event in events:
            timestamp = event_time(event)
            self.coordinator.process(event)
            last_seen = timestamp if last_seen is None else max(last_seen, timestamp)
            if next_sample is None:
                next_sample = timestamp
            if timestamp >= next_sample:
                yield from self.sample(capture, timestamp)
                last_sampled = timestamp
                next_sample = timestamp + self.interval
        if last_seen is not None and last_sampled != last_seen:
            yield from self.sample(capture, last_seen)

    def sample(self, capture: CaptureSpec, timestamp: datetime) -> tuple[FeatureRow, ...]:
        families = (capture.threat_family,) if capture.label == "attack" else tuple(self.extractors)
        if capture.label == "attack" and not capture.active_label(timestamp):
            return ()
        rows: list[FeatureRow] = []
        for family in families:
            manager = getattr(self, family)
            for key, state in manager.items():
                if family == "exfil":
                    feature = self.extractors[family].extract(key, state, manager, timestamp)
                else:
                    feature = self.extractors[family].extract(key, state, timestamp)
                if not self._subject_matches(capture, family, feature.subject):
                    continue
                rule = self.detectors[family].detect(feature)
                label = f"{family}_like" if capture.label == "attack" else "benign_like"
                values = (
                    raw_feature_values(family, feature)
                    if family in {"ddos", "scan", "exfil", "beacon"}
                    else _json_feature_values(feature)
                )
                rows.append(FeatureRow(
                    capture.capture_id, capture.dataset_name, capture.split_group,
                    capture.role, family, label, timestamp, feature.subject,
                    values, rule.score, rule.disposition,
                ))
        return tuple(rows)

    @staticmethod
    def _subject_matches(capture: CaptureSpec, family: str, subject: str) -> bool:
        metadata = capture.metadata
        wanted: tuple[str, ...]
        if family == "ddos":
            wanted = tuple(str(value) for value in metadata.get("victim_ips", ()))
            return not wanted or subject in wanted
        if family == "scan":
            wanted = tuple(str(value) for value in metadata.get("attacker_ips", ()))
            return not wanted or subject in wanted
        if family in {"exfil", "beacon"}:
            sources = tuple(str(value) for value in metadata.get("source_ips", ()))
            destinations = tuple(str(value) for value in metadata.get("destination_ips", ()))
            source, _, remainder = subject.partition("->")
            destination = (
                remainder.rsplit("/", 1)[0].rsplit(":", 1)[0]
                if family == "beacon" else remainder
            )
            return (not sources or source in sources) and (not destinations or destination in destinations)
        return True


def cache_key(capture: CaptureSpec, *, interval: timedelta) -> str:
    stat = capture.pcap_path.stat()
    payload = {
        "capture": capture.capture_id,
        "pcap": str(capture.pcap_path.resolve()),
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
        "interval_seconds": interval.total_seconds(),
        "schemas": {family: schema_manifest(family)["schema_sha256"] for family in ("ddos", "scan", "exfil", "beacon")},
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def _json_feature_values(feature: object) -> dict[str, object]:
    values = {
        item.name: getattr(feature, item.name)
        for item in fields(feature)  # type: ignore[arg-type]
        if item.name not in {"subject", "timestamp"}
    }
    return json.loads(json.dumps(values, default=str))


def write_cache(path: Path, rows: Iterable[FeatureRow]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    count = 0
    with temporary.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row.to_dict(), sort_keys=True) + "\n")
            count += 1
    temporary.replace(path)
    return count
