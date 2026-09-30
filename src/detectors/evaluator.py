"""Periodic feature extraction and rule evaluation over bounded state tables."""

from __future__ import annotations

from datetime import datetime, timedelta

from src.detectors.models import DetectorResult
from src.detectors.rules import (
    BeaconDetector,
    DDoSDetector,
    DNSDetector,
    EncryptedTrafficDetector,
    ExfilDetector,
    ScanDetector,
)
from src.features.extractors import (
    BeaconFeatureExtractor,
    DDoSFeatureExtractor,
    DNSFeatureExtractor,
    EncryptedTrafficFeatureExtractor,
    ExfilFeatureExtractor,
    ScanFeatureExtractor,
)
from src.states.beacon import BeaconStateManager
from src.states.ddos import DDoSStateManager
from src.states.dns import DNSStateManager
from src.states.encrypted import EncryptedStateManager
from src.states.exfil import ExfilStateManager
from src.states.scan import ScanStateManager
from src.ml.inference import MLInferenceEngine
from src.ml.models import MLResult


class PeriodicDetectorEvaluator:
    """Run bounded state scans only on a configurable event-time cadence."""

    def __init__(
        self,
        *,
        ddos_manager: DDoSStateManager,
        scan_manager: ScanStateManager,
        exfil_manager: ExfilStateManager,
        beacon_manager: BeaconStateManager,
        dns_manager: DNSStateManager | None = None,
        encrypted_manager: EncryptedStateManager | None = None,
        evaluation_interval: timedelta = timedelta(seconds=10),
        ddos_detector: DDoSDetector | None = None,
        scan_detector: ScanDetector | None = None,
        exfil_detector: ExfilDetector | None = None,
        beacon_detector: BeaconDetector | None = None,
        dns_detector: DNSDetector | None = None,
        encrypted_detector: EncryptedTrafficDetector | None = None,
        ml_engine: MLInferenceEngine | None = None,
    ) -> None:
        if evaluation_interval <= timedelta(0):
            raise ValueError("detector evaluation interval must be positive")
        self.ddos_manager = ddos_manager
        self.scan_manager = scan_manager
        self.exfil_manager = exfil_manager
        self.beacon_manager = beacon_manager
        self.dns_manager = dns_manager
        self.encrypted_manager = encrypted_manager
        self.evaluation_interval = evaluation_interval
        self.ddos_extractor = DDoSFeatureExtractor(ddos_manager.config)
        self.scan_extractor = ScanFeatureExtractor(scan_manager.config)
        self.exfil_extractor = ExfilFeatureExtractor(exfil_manager.config)
        self.beacon_extractor = BeaconFeatureExtractor(beacon_manager.config)
        self.dns_extractor = (
            DNSFeatureExtractor(dns_manager.config) if dns_manager is not None else None
        )
        self.encrypted_extractor = (
            EncryptedTrafficFeatureExtractor(encrypted_manager.config)
            if encrypted_manager is not None
            else None
        )
        self.ddos_detector = ddos_detector or DDoSDetector()
        self.scan_detector = scan_detector or ScanDetector()
        self.exfil_detector = exfil_detector or ExfilDetector()
        self.beacon_detector = beacon_detector or BeaconDetector()
        self.dns_detector = dns_detector or DNSDetector()
        self.encrypted_detector = encrypted_detector or EncryptedTrafficDetector()
        self.ml_engine = ml_engine
        self.last_ml_results: tuple[MLResult, ...] = ()
        self._last_evaluation_at: datetime | None = None
        self.evaluation_count = 0

    def maybe_evaluate(self, now: datetime) -> tuple[DetectorResult, ...]:
        self.last_ml_results = ()
        if self._last_evaluation_at is not None:
            if now < self._last_evaluation_at:
                return ()
            if now - self._last_evaluation_at < self.evaluation_interval:
                return ()
        self._last_evaluation_at = now
        self.evaluation_count += 1
        results = self.evaluate(now)
        if self.ml_engine is not None:
            self.last_ml_results = self.evaluate_ml(now)
        return results

    def evaluate_ml(self, now: datetime) -> tuple[MLResult, ...]:
        if self.ml_engine is None:
            return ()
        results: list[MLResult] = []
        groups = (
            ("ddos", self.ddos_manager.items(), lambda key, state: self.ddos_extractor.extract(key, state, now)),
            ("scan", self.scan_manager.items(), lambda key, state: self.scan_extractor.extract(key, state, now)),
            ("exfil", self.exfil_manager.items(), lambda key, state: self.exfil_extractor.extract(key, state, self.exfil_manager, now)),
            ("beacon", self.beacon_manager.items(), lambda key, state: self.beacon_extractor.extract(key, state, now)),
        )
        for family, items, extract in groups:
            for key, state in items:
                result = self.ml_engine.infer_feature(family, extract(key, state))
                if result is not None:
                    results.append(result)
        return tuple(results)

    def evaluate(self, now: datetime) -> tuple[DetectorResult, ...]:
        results: list[DetectorResult] = []
        for key, state in self.ddos_manager.items():
            results.append(self.ddos_detector.detect(self.ddos_extractor.extract(key, state, now)))
        for key, state in self.scan_manager.items():
            results.append(self.scan_detector.detect(self.scan_extractor.extract(key, state, now)))
        for key, state in self.exfil_manager.items():
            results.append(self.exfil_detector.detect(self.exfil_extractor.extract(key, state, self.exfil_manager, now)))
        for key, state in self.beacon_manager.items():
            results.append(self.beacon_detector.detect(self.beacon_extractor.extract(key, state, now)))
        if self.dns_manager is not None and self.dns_extractor is not None:
            for key, state in self.dns_manager.items():
                results.append(
                    self.dns_detector.detect(
                        self.dns_extractor.extract(key, state, now)
                    )
                )
        if self.encrypted_manager is not None and self.encrypted_extractor is not None:
            for key, state in self.encrypted_manager.items():
                results.append(
                    self.encrypted_detector.detect(
                        self.encrypted_extractor.extract(key, state, now)
                    )
                )
        return tuple(results)
