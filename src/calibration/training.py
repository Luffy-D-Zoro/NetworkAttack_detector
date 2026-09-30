"""Grouped model comparison and per-family fusion tuning for cached rows."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Iterable

import joblib
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from src.calibration.metrics import binary_metrics, select_threshold
from src.ml.schema import FAMILY_FEATURES, schema_manifest


def load_feature_rows(paths: Iterable[Path], family: str) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for path in paths:
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                row = json.loads(line)
                if row.get("family") == family:
                    rows.append(row)
    roles: dict[str, set[str]] = {}
    for row in rows:
        roles.setdefault(str(row["split_group"]), set()).add(str(row["role"]))
    leaking = {group: value for group, value in roles.items() if len(value) > 1}
    if leaking:
        raise ValueError(f"split-group leakage detected: {leaking}")
    if {str(row["role"]) for row in rows} != {"train", "validation", "test"}:
        raise ValueError("train, validation, and untouched test rows are all required")
    return rows


def _vector(family: str, row: dict[str, object]) -> list[float]:
    raw = row["features"]
    if not isinstance(raw, dict) or set(raw) != set(FAMILY_FEATURES[family]):
        raise ValueError(f"{family} cached feature schema/order is incompatible")
    values: list[float] = []
    for name in FAMILY_FEATURES[family]:
        value = raw[name]
        values.extend((0.0 if value is None else float(value), 0.0 if value is None else 1.0))
    return values


def _candidate_models(seed: int) -> dict[str, object]:
    return {
        "logistic_regression": make_pipeline(
            StandardScaler(),
            LogisticRegression(max_iter=2_000, class_weight="balanced", random_state=seed),
        ),
        "random_forest": RandomForestClassifier(
            n_estimators=200, max_depth=10, min_samples_leaf=2,
            class_weight="balanced", random_state=seed, n_jobs=1,
        ),
        "hist_gradient_boosting": HistGradientBoostingClassifier(
            max_iter=150, max_leaf_nodes=31, min_samples_leaf=10,
            class_weight="balanced", random_state=seed,
        ),
    }


def train_behavioral_family(
    *, family: str, rows: list[dict[str, object]], output_dir: Path,
    seed: int = 2404,
) -> dict[str, object]:
    if family not in FAMILY_FEATURES:
        raise ValueError(f"unsupported behavioral family {family!r}")
    partitions: dict[str, list[dict[str, object]]] = {
        role: [row for row in rows if row["role"] == role]
        for role in ("train", "validation", "test")
    }
    x = {role: [_vector(family, row) for row in selected] for role, selected in partitions.items()}
    y = {
        role: [str(row["label"]) for row in selected]
        for role, selected in partitions.items()
    }
    candidates: dict[str, dict[str, object]] = {}
    fitted: dict[str, object] = {}
    for name, model in _candidate_models(seed).items():
        model.fit(x["train"], y["train"])
        scores = model.predict_proba(x["validation"])[:, 1].tolist()
        validation_truth = [int(value == f"{family}_like") for value in y["validation"]]
        threshold, metrics = select_threshold(validation_truth, scores, maximum_fpr=0.02)
        candidates[name] = {"threshold": threshold, "validation_metrics": metrics}
        fitted[name] = model
    selected_name = max(
        candidates,
        key=lambda name: (
            float(candidates[name]["validation_metrics"]["pr_auc"] or 0.0),
            float(candidates[name]["validation_metrics"]["f1"]),
            -float(candidates[name]["validation_metrics"]["false_positive_rate"]),
            name == "logistic_regression",
        ),
    )
    model = fitted[selected_name]
    threshold = float(candidates[selected_name]["threshold"])
    test_scores = model.predict_proba(x["test"])[:, 1].tolist()
    test_metrics = binary_metrics(
        [int(value == f"{family}_like") for value in y["test"]],
        [int(value >= threshold) for value in test_scores], test_scores
    )
    selected_validation_scores = model.predict_proba(x["validation"])[:, 1].tolist()
    fusion = tune_fusion(
        partitions["validation"], selected_validation_scores,
        ml_threshold=threshold,
    )
    test_fusion_metrics = evaluate_fusion(
        partitions["test"], test_scores,
        rule_weight=float(fusion["rule_weight"]),
        ml_weight=float(fusion["ml_weight"]),
        alert_threshold=float(fusion["fused_alert_threshold"]),
        ml_threshold=threshold,
    )
    manifest = schema_manifest(family)
    manifest.update({
        "model_name": f"{family}_{selected_name}",
        "model_version": "realdata-behavior-v2",
        "algorithm": selected_name,
        "classes": ["benign_like", f"{family}_like"],
        "score_semantics": "uncalibrated classifier score; use validation-selected threshold",
        "recommended_ml_threshold": threshold,
        "recommended_fusion": fusion,
        "split_method": "manifest capture/scenario/day split_group; test untouched until final evaluation",
        "sample_counts": {role: len(value) for role, value in partitions.items()},
        "class_distribution": {
            role: dict(Counter(str(row["label"]) for row in value))
            for role, value in partitions.items()
        },
        "candidate_validation": candidates,
        "test_metrics": test_metrics,
        "test_fusion_metrics": test_fusion_metrics,
    })
    output_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump({
        "model": model, "model_name": manifest["model_name"],
        "model_version": manifest["model_version"], "family": family,
        "schema_sha256": manifest["schema_sha256"],
        "score_calibrated": False,
    }, output_dir / f"{family}.joblib")
    (output_dir / f"{family}.manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest


def tune_fusion(
    validation_rows: list[dict[str, object]], scores: list[float],
    *, ml_threshold: float,
) -> dict[str, object]:
    candidates: list[tuple[float, float, float, dict[str, object]]] = []
    for rule_weight in (0.25, 0.4, 0.5, 0.6, 0.75):
        ml_weight = 1.0 - rule_weight
        for alert_threshold in (0.45, 0.5, 0.55, 0.6, 0.65, 0.7, 0.75, 0.8):
            metrics = evaluate_fusion(
                validation_rows, scores, rule_weight=rule_weight,
                ml_weight=ml_weight, alert_threshold=alert_threshold,
                ml_threshold=ml_threshold,
            )
            candidates.append((
                float(metrics["f1"]),
                -float(metrics["false_positive_rate"]),
                float(metrics["recall"]),
                {"rule_weight": rule_weight, "ml_weight": ml_weight,
                 "fused_alert_threshold": alert_threshold,
                 "validation_metrics": metrics},
            ))
    return max(candidates, key=lambda item: item[:3])[3]


def evaluate_fusion(
    rows: list[dict[str, object]], scores: list[float], *,
    rule_weight: float, ml_weight: float, alert_threshold: float,
    ml_threshold: float,
) -> dict[str, object]:
    if len(rows) != len(scores):
        raise ValueError("fusion rows and scores must have equal length")
    truth: list[int] = []
    predictions: list[int] = []
    confidences: list[float] = []
    for row, ml_score in zip(rows, scores):
        positive = str(row["label"]) != "benign_like"
        rule_suspicious = row["rule_disposition"] == "suspicious"
        ml_suspicious = ml_score >= ml_threshold
        confidence = rule_weight * float(row["rule_score"]) + ml_weight * ml_score
        if rule_suspicious and ml_suspicious:
            confidence += 0.05
        elif rule_suspicious != ml_suspicious:
            confidence *= 0.75
        confidence = max(0.0, min(1.0, confidence))
        truth.append(int(positive))
        predictions.append(int((rule_suspicious or ml_suspicious) and confidence >= alert_threshold))
        confidences.append(confidence)
    return binary_metrics(truth, predictions, confidences)
