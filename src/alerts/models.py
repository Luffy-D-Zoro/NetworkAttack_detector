"""Canonical JSON-serializable final alert model."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal, Mapping

Severity = Literal["low", "medium", "high", "critical"]


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class StructuredAlert:
    alert_id: str
    timestamp: datetime
    threat_family: str
    threat_class: str
    subject: str
    confidence: float
    severity: Severity
    evidence: tuple[str, ...]
    supporting_features: tuple[str, ...]
    detection_sources: tuple[str, ...]
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: int | None = None
    rule_score: float | None = None
    ml_score: float | None = None
    rule_disposition: str | None = None
    ml_prediction: str | None = None
    model_name: str | None = None
    model_version: str | None = None

    def __post_init__(self) -> None:
        if not self.alert_id:
            raise ValueError("alert_id must not be empty")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("alert confidence must be between zero and one")
        for name, value in (("rule_score", self.rule_score), ("ml_score", self.ml_score)):
            if value is not None and not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be between zero and one")
        if self.severity not in {"low", "medium", "high", "critical"}:
            raise ValueError("unsupported alert severity")
        if not self.detection_sources:
            raise ValueError("an alert must have at least one detection source")

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "timestamp": _timestamp(self.timestamp),
            "threat_family": self.threat_family,
            "threat_class": self.threat_class,
            "subject": self.subject,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "confidence": self.confidence,
            "severity": self.severity,
            "rule_score": self.rule_score,
            "ml_score": self.ml_score,
            "rule_disposition": self.rule_disposition,
            "ml_prediction": self.ml_prediction,
            "evidence": list(self.evidence),
            "supporting_features": list(self.supporting_features),
            "model_name": self.model_name,
            "model_version": self.model_version,
            "detection_sources": list(self.detection_sources),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> StructuredAlert:
        timestamp = datetime.fromisoformat(str(value["timestamp"]).replace("Z", "+00:00"))
        return cls(
            alert_id=str(value["alert_id"]), timestamp=timestamp,
            threat_family=str(value["threat_family"]),
            threat_class=str(value["threat_class"]), subject=str(value["subject"]),
            confidence=float(value["confidence"]), severity=value["severity"],
            evidence=tuple(str(item) for item in value["evidence"]),
            supporting_features=tuple(str(item) for item in value["supporting_features"]),
            detection_sources=tuple(str(item) for item in value["detection_sources"]),
            src_ip=value.get("src_ip"), dst_ip=value.get("dst_ip"),
            src_port=value.get("src_port"), dst_port=value.get("dst_port"),
            protocol=value.get("protocol"), rule_score=value.get("rule_score"),
            ml_score=value.get("ml_score"), rule_disposition=value.get("rule_disposition"),
            ml_prediction=value.get("ml_prediction"), model_name=value.get("model_name"),
            model_version=value.get("model_version"),
        )
