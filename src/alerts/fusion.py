"""Transparent configurable rule/ML fusion without learned ensembling."""

from __future__ import annotations

import ipaddress
import uuid
from dataclasses import dataclass
from typing import Iterable

from src.alerts.models import Severity, StructuredAlert
from src.detectors.models import DetectorResult
from src.ml.models import MLResult

_ALERT_NAMESPACE = uuid.UUID("a6945927-0a2d-4af9-ad22-8edb748f25c4")
_RULE_FAMILIES = {
    "ddos_statistical": "ddos",
    "scan_statistical": "scan",
    "exfil_statistical": "exfil",
    "beacon_statistical": "beacon",
    "dns_statistical": "dns",
    "encrypted_traffic_statistical": "encrypted",
}
_PUBLIC_FAMILY = {
    "ddos": "ddos", "scan": "scan", "exfil": "exfiltration",
    "beacon": "beaconing", "dns": "dns", "dga": "dns",
    "encrypted": "encrypted_traffic",
}
_THREAT_CLASS = {
    "ddos": "ddos_like", "scan": "scan_like",
    "exfil": "exfiltration_like", "beacon": "beaconing_like",
    "encrypted": "encrypted_traffic_anomaly",
}


@dataclass(frozen=True, slots=True)
class SeverityConfig:
    medium_threshold: float = 0.65
    high_threshold: float = 0.80
    critical_threshold: float = 0.95
    critical_minimum_evidence: int = 4

    def __post_init__(self) -> None:
        if not 0.0 <= self.medium_threshold <= self.high_threshold <= self.critical_threshold <= 1.0:
            raise ValueError("severity thresholds must be ordered within zero and one")
        if self.critical_minimum_evidence <= 0:
            raise ValueError("critical evidence count must be positive")

    def classify(self, confidence: float, evidence_count: int) -> Severity:
        if confidence >= self.critical_threshold and evidence_count >= self.critical_minimum_evidence:
            return "critical"
        if confidence >= self.high_threshold:
            return "high"
        if confidence >= self.medium_threshold:
            return "medium"
        return "low"


@dataclass(frozen=True, slots=True)
class FamilyFusionConfig:
    rule_weight: float = 0.5
    ml_weight: float = 0.5
    agreement_bonus: float = 0.05
    disagreement_multiplier: float = 0.75
    fused_alert_threshold: float = 0.65
    rule_only_threshold: float = 0.65
    ml_only_threshold: float = 0.70
    ml_only_discount: float = 0.85
    allow_ml_only_when_rule_insufficient: bool = True
    allow_ml_only_without_rule: bool = True

    def __post_init__(self) -> None:
        values = (
            self.rule_weight, self.ml_weight, self.agreement_bonus,
            self.disagreement_multiplier, self.fused_alert_threshold,
            self.rule_only_threshold, self.ml_only_threshold,
            self.ml_only_discount,
        )
        if any(not 0.0 <= value <= 1.0 for value in values):
            raise ValueError("fusion scores, weights, and thresholds must be within zero and one")
        if self.rule_weight + self.ml_weight <= 0:
            raise ValueError("at least one fusion weight must be positive")


@dataclass(frozen=True, slots=True)
class FusionConfig(FamilyFusionConfig):
    # Selected on the DGA research-corpus validation tuning split; the final
    # held-out test split was not used to choose it.
    dga_alert_threshold: float = 0.891
    severity: SeverityConfig = SeverityConfig()
    family_overrides: tuple[tuple[str, FamilyFusionConfig], ...] = ()

    def __post_init__(self) -> None:
        FamilyFusionConfig.__post_init__(self)
        if not 0.0 <= self.dga_alert_threshold <= 1.0:
            raise ValueError("DGA alert threshold must be within zero and one")
        families = [family for family, _ in self.family_overrides]
        if len(families) != len(set(families)):
            raise ValueError("family fusion overrides must be unique")

    def for_family(self, family: str) -> FamilyFusionConfig:
        return dict(self.family_overrides).get(family, FamilyFusionConfig(
            rule_weight=self.rule_weight, ml_weight=self.ml_weight,
            agreement_bonus=self.agreement_bonus,
            disagreement_multiplier=self.disagreement_multiplier,
            fused_alert_threshold=self.fused_alert_threshold,
            rule_only_threshold=self.rule_only_threshold,
            ml_only_threshold=self.ml_only_threshold,
            ml_only_discount=self.ml_only_discount,
            allow_ml_only_when_rule_insufficient=self.allow_ml_only_when_rule_insufficient,
            allow_ml_only_without_rule=self.allow_ml_only_without_rule,
        ))


class AlertFusionEngine:
    """Produce candidate alerts; persistence and cooldown are separate concerns."""

    def __init__(self, config: FusionConfig | None = None) -> None:
        self.config = config or FusionConfig()

    def fuse(
        self,
        rule_results: Iterable[DetectorResult],
        ml_results: Iterable[MLResult],
    ) -> tuple[StructuredAlert, ...]:
        rules = tuple(rule_results)
        models = tuple(ml_results)
        indexed_ml = {
            (result.family, result.subject, result.timestamp): result
            for result in models if result.family in {"ddos", "scan", "exfil", "beacon"}
        }
        consumed: set[tuple[str, str, object]] = set()
        alerts: list[StructuredAlert] = []

        for rule in rules:
            family = _RULE_FAMILIES.get(rule.detector)
            if family is None:
                continue
            if family in {"ddos", "scan", "exfil", "beacon"}:
                key = (family, rule.subject, rule.timestamp)
                model = indexed_ml.get(key)
                if model is not None:
                    consumed.add(key)
                alert = self._behavioral(rule, model, family)
            else:
                alert = self._rule_only(rule, family)
            if alert is not None:
                alerts.append(alert)

        for model in models:
            if model.family == "dga":
                alert = self._dga(model)
            elif model.family in {"ddos", "scan", "exfil", "beacon"}:
                key = (model.family, model.subject, model.timestamp)
                alert = None if key in consumed else self._ml_only(model, model.family, rule=None)
            else:
                alert = None
            if alert is not None:
                alerts.append(alert)
        return tuple(alerts)

    def _behavioral(self, rule: DetectorResult, model: MLResult | None, family: str) -> StructuredAlert | None:
        config = self.config.for_family(family)
        if model is None:
            return self._rule_only(rule, family)
        if rule.disposition == "insufficient_data":
            if not config.allow_ml_only_when_rule_insufficient:
                return None
            return self._ml_only(model, family, rule=rule)

        ml_support = _suspicious_support(model)
        rule_suspicious = rule.disposition == "suspicious"
        ml_suspicious = model.predicted_class != "benign_like"
        weight_sum = config.rule_weight + config.ml_weight
        confidence = (
            config.rule_weight * rule.score + config.ml_weight * ml_support
        ) / weight_sum
        if rule_suspicious and ml_suspicious:
            confidence += config.agreement_bonus
        elif rule_suspicious != ml_suspicious:
            confidence *= config.disagreement_multiplier
        confidence = _bounded(confidence)
        if not (rule_suspicious or ml_suspicious) or confidence < config.fused_alert_threshold:
            return None
        return self._alert(family, rule.subject, rule.timestamp, confidence, rule, model)

    def _rule_only(self, rule: DetectorResult, family: str) -> StructuredAlert | None:
        config = self.config.for_family(family)
        if rule.disposition != "suspicious" or rule.score < config.rule_only_threshold:
            return None
        return self._alert(family, rule.subject, rule.timestamp, rule.score, rule, None)

    def _ml_only(self, model: MLResult, family: str, *, rule: DetectorResult | None) -> StructuredAlert | None:
        config = self.config.for_family(family)
        if rule is None and not config.allow_ml_only_without_rule:
            return None
        if model.predicted_class == "benign_like":
            return None
        confidence = _bounded(model.confidence * config.ml_only_discount)
        if confidence < config.ml_only_threshold:
            return None
        return self._alert(family, model.subject, model.timestamp, confidence, rule, model)

    def _dga(self, model: MLResult) -> StructuredAlert | None:
        if model.predicted_class != "dga_like" or model.confidence < self.config.dga_alert_threshold:
            return None
        return self._alert("dga", model.subject, model.timestamp, model.confidence, None, model)

    def _alert(
        self, family: str, subject: str, timestamp, confidence: float,
        rule: DetectorResult | None, model: MLResult | None,
    ) -> StructuredAlert:
        public_family = _PUBLIC_FAMILY[family]
        threat_class = _dns_rule_class(rule) if family == "dns" else (
            "dga_like" if family == "dga" else _THREAT_CLASS[family]
        )
        evidence = list(rule.evidence if rule is not None else ())
        if model is not None:
            score_description = (
                "calibrated research-corpus score"
                if model.score_calibrated
                else "uncalibrated prototype confidence"
            )
            evidence.append(
                f"ML {model.model_name} predicted {model.predicted_class} at "
                f"{model.confidence:.3f} {score_description}"
            )
        sources = tuple(source for source, present in (("rule", rule is not None), ("ml", model is not None)) if present)
        features = set(rule.available_features if rule is not None else ())
        if model is not None:
            features.update(model.features_used)
        endpoints = _endpoints(family, subject, model)
        identity = "|".join((timestamp.isoformat(), public_family, threat_class, subject, *sources))
        return StructuredAlert(
            alert_id=str(uuid.uuid5(_ALERT_NAMESPACE, identity)), timestamp=timestamp,
            threat_family=public_family, threat_class=threat_class, subject=subject,
            confidence=confidence,
            severity=self.config.severity.classify(confidence, len(evidence)),
            evidence=tuple(evidence), supporting_features=tuple(sorted(features)),
            detection_sources=sources, rule_score=rule.score if rule is not None else None,
            ml_score=_suspicious_support(model) if model is not None else None,
            rule_disposition=rule.disposition if rule is not None else None,
            ml_prediction=model.predicted_class if model is not None else None,
            model_name=model.model_name if model is not None else None,
            model_version=model.model_version if model is not None else None,
            **endpoints,
        )


def _bounded(value: float) -> float:
    return max(0.0, min(1.0, value))


def _suspicious_support(model: MLResult) -> float:
    return 1.0 - model.confidence if model.predicted_class == "benign_like" else model.confidence


def _dns_rule_class(rule: DetectorResult | None) -> str:
    evidence = tuple(item.lower() for item in (rule.evidence if rule is not None else ()))
    kinds = {
        "dns_tunneling_like" for item in evidence if "tunneling-like" in item
    } | {
        "dns_dga_behavior_like" for item in evidence if "dga-like" in item
    } | {
        "abnormal_dns_querying" for item in evidence if "abnormal" in item
    }
    return next(iter(kinds)) if len(kinds) == 1 else "dns_behavior_anomaly"


def _endpoints(family: str, subject: str, model: MLResult | None) -> dict[str, object | None]:
    result: dict[str, object | None] = {
        "src_ip": None, "dst_ip": None, "src_port": None,
        "dst_port": None, "protocol": None,
    }
    try:
        if family == "ddos":
            result["dst_ip"] = str(ipaddress.ip_address(subject))
        elif family in {"scan", "dns"}:
            result["src_ip"] = str(ipaddress.ip_address(subject))
        elif family == "dga" and model is not None:
            domain = str(model.features_used.get("normalized_dns_query", ""))
            suffix = f":{domain}"
            source = subject[:-len(suffix)] if domain and subject.endswith(suffix) else ""
            result["src_ip"] = str(ipaddress.ip_address(source))
        elif family == "exfil":
            source, destination = subject.split("->", 1)
            result.update(src_ip=str(ipaddress.ip_address(source)), dst_ip=str(ipaddress.ip_address(destination)))
        elif family in {"beacon", "encrypted"}:
            source, remainder = subject.split("->", 1)
            parts = remainder.rsplit("/", 2)
            destination, port = parts[0].rsplit(":", 1)
            protocol = parts[1]
            result.update(
                src_ip=str(ipaddress.ip_address(source)), dst_ip=str(ipaddress.ip_address(destination)),
                dst_port=int(port), protocol=int(protocol),
            )
    except (ValueError, IndexError):
        pass
    return result
