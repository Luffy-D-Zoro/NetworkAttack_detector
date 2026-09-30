"""Internal detector output; this is deliberately not an alert model."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

DetectorDisposition = Literal["insufficient_data", "benign_like", "suspicious"]


@dataclass(frozen=True, slots=True)
class DetectorResult:
    detector: str
    subject: str
    timestamp: datetime
    score: float
    triggered: bool
    disposition: DetectorDisposition
    evidence: tuple[str, ...]
    available_features: tuple[str, ...]

    def __post_init__(self) -> None:
        if not 0.0 <= self.score <= 1.0:
            raise ValueError("detector score must be between zero and one")
        if self.triggered != (self.disposition == "suspicious"):
            raise ValueError("triggered must match the suspicious disposition")
