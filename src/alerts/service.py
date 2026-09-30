"""Fuse, suppress, and persist alerts without retaining an alert history."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Iterable

from src.alerts.fusion import AlertFusionEngine
from src.alerts.models import StructuredAlert
from src.alerts.storage import AlertRepository, AlertStorageError
from src.alerts.suppression import AlertSuppressor
from src.detectors.models import DetectorResult
from src.ml.models import MLResult

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class AlertBatch:
    alerts: tuple[StructuredAlert, ...]
    persistence_failures: int = 0


class AlertService:
    def __init__(
        self, *, repository: AlertRepository | None = None,
        fusion: AlertFusionEngine | None = None,
        suppressor: AlertSuppressor | None = None,
    ) -> None:
        self.repository = repository
        self.fusion = fusion or AlertFusionEngine()
        self.suppressor = suppressor or AlertSuppressor()
        self.persistence_failure_count = 0
        self.last_persistence_error: str | None = None

    def process(
        self, rule_results: Iterable[DetectorResult], ml_results: Iterable[MLResult],
    ) -> AlertBatch:
        emitted: list[StructuredAlert] = []
        failures = 0
        for alert in self.fusion.fuse(rule_results, ml_results):
            if not self.suppressor.accept(alert):
                continue
            emitted.append(alert)
            if self.repository is None:
                continue
            try:
                self.repository.insert(alert)
            except AlertStorageError as exc:
                failures += 1
                self.persistence_failure_count += 1
                self.last_persistence_error = str(exc)
                LOGGER.warning("Final alert was emitted but not persisted: %s", exc)
        return AlertBatch(tuple(emitted), failures)
