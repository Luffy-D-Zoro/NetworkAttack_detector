"""Reproducible Phase 4A prototype model training and artifact persistence."""

from __future__ import annotations

import csv
import json
import platform
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import joblib
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

from src.ml.schema import FAMILY_FEATURES, schema_manifest, vectorize
from src.ml.training_data import generate_dga_samples, generate_flow_samples

MODEL_VERSION = "phase4a-prototype-v1"


def _metrics(y_true: list[str], y_pred: list[str], labels: list[str]) -> dict[str, Any]:
    precision, recall, f1, support = precision_recall_fscore_support(
        y_true, y_pred, labels=labels, zero_division=0
    )
    return {
        "accuracy": accuracy_score(y_true, y_pred),
        "per_class": {
            label: {"precision": precision[i], "recall": recall[i], "f1": f1[i], "support": int(support[i])}
            for i, label in enumerate(labels)
        },
        "macro_precision": sum(precision) / len(precision),
        "macro_recall": sum(recall) / len(recall),
        "macro_f1": sum(f1) / len(f1),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=labels).tolist(),
        "label_order": labels,
    }


def train_all(
    *, output_dir: Path, data_dir: Path, seed: int = 2404,
    flow_samples_per_class: int = 48, dga_samples_per_class: int = 240,
) -> dict[str, Any]:
    started = time.perf_counter()
    output_dir.mkdir(parents=True, exist_ok=True)
    data_dir.mkdir(parents=True, exist_ok=True)
    flow_samples = generate_flow_samples(seed=seed, samples_per_class=flow_samples_per_class)

    with (data_dir / "flow_scenarios.jsonl").open("w", encoding="utf-8") as handle:
        for sample in flow_samples:
            _, raw = vectorize(sample.family, sample.feature)
            handle.write(json.dumps({
                "scenario_id": sample.scenario_id, "family": sample.family,
                "label": sample.label, "features": raw,
            }, sort_keys=True) + "\n")

    model_summaries: dict[str, Any] = {}
    for family in FAMILY_FEATURES:
        selected = [sample for sample in flow_samples if sample.family == family]
        X = [vectorize(family, sample.feature)[0] for sample in selected]
        y = [sample.label for sample in selected]
        indices = list(range(len(selected)))
        train_indices, validation_indices = train_test_split(
            indices, test_size=0.25, random_state=seed, stratify=y
        )
        model = RandomForestClassifier(
            n_estimators=120, max_depth=8, min_samples_leaf=2,
            class_weight="balanced", random_state=seed, n_jobs=1,
        )
        model.fit([X[i] for i in train_indices], [y[i] for i in train_indices])
        y_validation = [y[i] for i in validation_indices]
        predicted = model.predict([X[i] for i in validation_indices]).tolist()
        labels = ["benign_like", f"{family}_like"]
        manifest = schema_manifest(family)
        manifest.update({
            "model_name": f"{family}_random_forest", "model_version": MODEL_VERSION,
            "algorithm": "sklearn.ensemble.RandomForestClassifier",
            "training_configuration": {
                "n_estimators": 120, "max_depth": 8, "min_samples_leaf": 2,
                "class_weight": "balanced", "random_state": seed, "n_jobs": 1,
                "validation_fraction": 0.25,
            },
            "classes": model.classes_.tolist(), "prototype_data": True,
            "training_seed": seed, "train_samples": len(train_indices),
            "validation_samples": len(validation_indices),
            "class_distribution": dict(sorted(Counter(y).items())),
        })
        bundle = {
            "model": model, "model_name": manifest["model_name"],
            "model_version": MODEL_VERSION, "family": family,
            "schema_sha256": manifest["schema_sha256"],
        }
        joblib.dump(bundle, output_dir / f"{family}.joblib")
        (output_dir / f"{family}.manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        model_summaries[family] = {**manifest, "metrics": _metrics(y_validation, predicted, labels)}

    dga_rows = generate_dga_samples(seed=seed, samples_per_class=dga_samples_per_class)
    with (data_dir / "dga_domains.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(("normalized_domain", "label"))
        writer.writerows(dga_rows)
    domains = [row[0] for row in dga_rows]
    labels_all = [row[1] for row in dga_rows]
    X_train, X_validation, y_train, y_validation = train_test_split(
        domains, labels_all, test_size=0.25, random_state=seed, stratify=labels_all
    )
    dga_model = Pipeline((
        ("tfidf", TfidfVectorizer(analyzer="char", ngram_range=(3, 5), lowercase=False, sublinear_tf=True, max_features=8_000)),
        ("classifier", LogisticRegression(max_iter=1_000, random_state=seed, class_weight="balanced")),
    ))
    dga_model.fit(X_train, y_train)
    dga_predicted = dga_model.predict(X_validation).tolist()
    vocabulary = dga_model.named_steps["tfidf"].get_feature_names_out().tolist()
    dga_manifest = {
        "schema_version": 1, "family": "dga", "model_name": "dns_dga_char_ngram",
        "model_version": MODEL_VERSION,
        "algorithm": "character 3-5 gram TF-IDF + LogisticRegression",
        "training_configuration": {
            "tfidf_analyzer": "char", "tfidf_ngram_range": [3, 5],
            "tfidf_sublinear_tf": True, "tfidf_max_features": 8_000,
            "logistic_max_iter": 1_000, "logistic_class_weight": "balanced",
            "random_state": seed, "validation_fraction": 0.25,
        },
        "input_schema": "normalized_dns_query_string",
        "normalization": "strip whitespace, remove trailing dot, lowercase",
        "feature_names": vocabulary, "classes": dga_model.classes_.tolist(),
        "prototype_data": True, "training_seed": seed,
        "train_samples": len(X_train), "validation_samples": len(X_validation),
        "class_distribution": dict(sorted(Counter(labels_all).items())),
    }
    import hashlib
    dga_manifest["schema_sha256"] = hashlib.sha256(
        json.dumps({k: v for k, v in dga_manifest.items() if k != "schema_sha256"}, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    joblib.dump({
        "model": dga_model, "model_name": dga_manifest["model_name"],
        "model_version": MODEL_VERSION, "family": "dga",
        "schema_sha256": dga_manifest["schema_sha256"],
    }, output_dir / "dga.joblib")
    (output_dir / "dga.manifest.json").write_text(
        json.dumps(dga_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    model_summaries["dga"] = {
        **{key: value for key, value in dga_manifest.items() if key != "feature_names"},
        "feature_count": len(vocabulary),
        "metrics": _metrics(y_validation, dga_predicted, ["benign_like", "dga_like"]),
    }

    summary = {
        "generated_at": datetime.now(UTC).isoformat(),
        "dataset_notice": "Prototype deterministic synthetic/lab validation only; metrics are not real-world detection accuracy.",
        "seed": seed, "python_version": platform.python_version(),
        "scikit_learn_version": sklearn.__version__,
        "flow_samples": len(flow_samples), "dga_samples": len(dga_rows),
        "models": model_summaries,
        "training_seconds": time.perf_counter() - started,
    }
    (output_dir / "validation_metrics.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return summary
