"""Stable runtime result types for independent ML inference."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Mapping


@dataclass(frozen=True, slots=True)
class MLResult:
    model_name: str
    model_version: str
    family: str
    subject: str
    timestamp: datetime
    predicted_class: str
    confidence: float
    features_used: Mapping[str, float | str | None]
    score_calibrated: bool = False

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("ML confidence must be between zero and one")
        object.__setattr__(self, "features_used", MappingProxyType(dict(self.features_used)))
