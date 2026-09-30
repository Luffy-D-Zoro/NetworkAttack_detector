"""Train the existing DGA algorithm on a grouped public research corpus."""

from __future__ import annotations

import csv
import hashlib
import json
import platform
import time
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path

import joblib
import sklearn
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.frozen import FrozenEstimator
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from src.calibration.metrics import binary_metrics, select_threshold
from src.ml.training_data import normalize_domain

DGA_MODEL_VERSION = "realdata-dga-v2"


def _hash(value: str, seed: int) -> int:
    return int.from_bytes(
        hashlib.blake2b(f"{seed}:{value}".encode(), digest_size=8).digest(), "big"
    )


def _read_corpus(path: Path, seed: int) -> tuple[dict[str, list[str]], dict[str, str], dict[str, str]]:
    by_role: dict[str, list[str]] = defaultdict(list)
    labels: dict[str, str] = {}
    dga_rows: dict[str, list[str]] = defaultdict(list)
    benign: list[str] = []
    with path.open(encoding="utf-8", newline="") as handle:
        for row in csv.reader(handle):
            if len(row) != 3:
                continue
            kind, family, raw_domain = row
            domain = normalize_domain(raw_domain)
            if not domain:
                continue
            if kind == "dga":
                dga_rows[family].append(domain)
            elif kind == "legit":
                benign.append(domain)
    families = sorted(dga_rows, key=lambda value: (_hash(value, seed), value))
    if len(families) < 8:
        raise ValueError("research corpus must contain multiple DGA families")
    test_count = max(2, round(len(families) * 0.16))
    validation_count = max(2, round(len(families) * 0.16))
    family_roles: dict[str, str] = {}
    for family in families[:test_count]:
        family_roles[family] = "test"
    for family in families[test_count:test_count + validation_count]:
        family_roles[family] = "validation"
    for family in families[test_count + validation_count:]:
        family_roles[family] = "train"
    for family, domains in dga_rows.items():
        role = family_roles[family]
        by_role[role].extend(domains)
        labels.update((domain, "dga_like") for domain in domains)
    for domain in benign:
        choice = _hash(domain, seed) % 100
        role = "train" if choice < 68 else "validation" if choice < 84 else "test"
        by_role[role].append(domain)
        labels[domain] = "benign_like"
    return by_role, family_roles, labels


def _balanced(
    domains: list[str], labels: dict[str, str], *, per_class: int, seed: int
) -> tuple[list[str], list[int]]:
    groups = {
        label: sorted(
            {domain for domain in domains if labels[domain] == label},
            key=lambda value: (_hash(value, seed), value),
        )[:per_class]
        for label in ("benign_like", "dga_like")
    }
    selected = groups["benign_like"] + groups["dga_like"]
    selected.sort(key=lambda value: (_hash(value, seed + 1), value))
    return selected, [int(labels[value] == "dga_like") for value in selected]


def train_research_dga(
    *, corpus_path: Path, output_dir: Path, seed: int = 2404,
    train_per_class: int = 30_000, validation_per_class: int = 10_000,
    test_per_class: int = 10_000,
) -> dict[str, object]:
    started = time.perf_counter()
    by_role, family_roles, labels = _read_corpus(corpus_path, seed)
    train_x, train_y = _balanced(by_role["train"], labels, per_class=train_per_class, seed=seed)
    validation_x, validation_y = _balanced(by_role["validation"], labels, per_class=validation_per_class, seed=seed + 2)
    test_x, test_y = _balanced(by_role["test"], labels, per_class=test_per_class, seed=seed + 3)
    calibration_x = [value for value in validation_x if _hash(value, seed + 4) % 2 == 0]
    tuning_x = [value for value in validation_x if _hash(value, seed + 4) % 2 == 1]
    calibration_y = [int(labels[value] == "dga_like") for value in calibration_x]
    tuning_y = [int(labels[value] == "dga_like") for value in tuning_x]

    base = Pipeline((
        ("tfidf", TfidfVectorizer(
            analyzer="char", ngram_range=(3, 5), lowercase=False,
            sublinear_tf=True, max_features=50_000, min_df=2,
        )),
        ("classifier", LogisticRegression(
            max_iter=1_000, random_state=seed, class_weight="balanced",
            solver="liblinear",
        )),
    ))
    base.fit(train_x, train_y)
    calibrated = CalibratedClassifierCV(
        FrozenEstimator(base), method="sigmoid", cv=None
    )
    calibrated.fit(calibration_x, calibration_y)
    tune_scores = calibrated.predict_proba(tuning_x)[:, 1].tolist()
    threshold, tuning_metrics = select_threshold(tuning_y, tune_scores, maximum_fpr=0.01)
    test_scores = calibrated.predict_proba(test_x)[:, 1].tolist()
    test_metrics = binary_metrics(
        test_y, [int(value >= threshold) for value in test_scores], test_scores
    )
    vocabulary = base.named_steps["tfidf"].get_feature_names_out().tolist()
    source_sha256 = hashlib.sha256(corpus_path.read_bytes()).hexdigest()
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, object] = {
        "schema_version": 2, "family": "dga",
        "model_name": "dns_dga_char_ngram",
        "model_version": DGA_MODEL_VERSION,
        "algorithm": "character 3-5 gram TF-IDF + class-weighted LogisticRegression + sigmoid calibration",
        "input_schema": "normalized_dns_query_string",
        "normalization": "strip whitespace, remove trailing dot, lowercase",
        "feature_names": vocabulary,
        "classes": calibrated.classes_.tolist(),
        "score_semantics": "sigmoid-calibrated held-out-family research-corpus score",
        "recommended_alert_threshold": threshold,
        "dataset": {
            "name": "DGA_domains_dataset",
            "source": "https://github.com/chrmor/DGA_domains_dataset",
            "sha256": source_sha256,
            "rows": sum(len(value) for value in by_role.values()),
            "family_roles": family_roles,
            "notice": "Public research corpus; held-out metrics are lab generalization results, not live-network accuracy.",
        },
        "training_configuration": {
            "seed": seed, "train_per_class_cap": train_per_class,
            "validation_per_class_cap": validation_per_class,
            "test_per_class_cap": test_per_class,
            "split": "DGA family held out by role; benign domains deterministically hashed by domain",
            "threshold_tuned_on": "validation tuning half only",
            "maximum_validation_false_positive_rate": 0.01,
        },
        "sample_counts": {
            "train": len(train_x), "calibration": len(calibration_x),
            "validation_tuning": len(tuning_x), "test": len(test_x),
        },
        "validation_metrics": tuning_metrics,
        "test_metrics": test_metrics,
        "python_version": platform.python_version(),
        "scikit_learn_version": sklearn.__version__,
    }
    manifest["schema_sha256"] = hashlib.sha256(
        json.dumps({k: v for k, v in manifest.items() if k != "schema_sha256"}, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    bundle = {
        "model": calibrated, "model_name": manifest["model_name"],
        "model_version": DGA_MODEL_VERSION, "family": "dga",
        "schema_sha256": manifest["schema_sha256"],
        "feature_names": vocabulary,
        "recommended_alert_threshold": threshold,
        "score_calibrated": True,
    }
    joblib.dump(bundle, output_dir / "dga.joblib")
    (output_dir / "dga.manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "training_seconds": time.perf_counter() - started,
        **{key: manifest[key] for key in ("model_name", "model_version", "algorithm", "sample_counts", "validation_metrics", "test_metrics", "dataset", "recommended_alert_threshold")},
    }
    (output_dir / "dga.realdata.metrics.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return report
