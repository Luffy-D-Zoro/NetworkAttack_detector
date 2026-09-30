"""Bounded event-time cooldown for repeated final alerts."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timedelta

from src.alerts.models import StructuredAlert

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass(frozen=True, slots=True)
class AlertSuppressionConfig:
    cooldown: timedelta = timedelta(minutes=5)
    material_confidence_increase: float = 0.15
    max_entries: int = 50_000

    def __post_init__(self) -> None:
        if self.cooldown <= timedelta(0):
            raise ValueError("alert cooldown must be positive")
        if not 0.0 <= self.material_confidence_increase <= 1.0:
            raise ValueError("material confidence increase must be within zero and one")
        if self.max_entries <= 0:
            raise ValueError("alert suppression capacity must be positive")


@dataclass(frozen=True, slots=True)
class _PriorAlert:
    timestamp: datetime
    confidence: float
    severity_rank: int


class AlertSuppressor:
    def __init__(self, config: AlertSuppressionConfig | None = None) -> None:
        self.config = config or AlertSuppressionConfig()
        self._recent: OrderedDict[tuple[str, str], _PriorAlert] = OrderedDict()
        self.capacity_evictions = 0
        self.suppressed_count = 0

    def accept(self, alert: StructuredAlert) -> bool:
        key = (alert.threat_family, alert.subject)
        previous = self._recent.get(key)
        rank = _SEVERITY_RANK[alert.severity]
        accepted = (
            previous is None
            or alert.timestamp >= previous.timestamp + self.config.cooldown
            or rank > previous.severity_rank
            or alert.confidence >= previous.confidence + self.config.material_confidence_increase
        )
        if not accepted:
            self.suppressed_count += 1
            return False
        if previous is not None and alert.timestamp < previous.timestamp:
            self.suppressed_count += 1
            return False
        self._recent[key] = _PriorAlert(alert.timestamp, alert.confidence, rank)
        self._recent.move_to_end(key)
        if len(self._recent) > self.config.max_entries:
            self._recent.popitem(last=False)
            self.capacity_evictions += 1
        return True

    def __len__(self) -> int:
        return len(self._recent)
