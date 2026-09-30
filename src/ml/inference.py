"""Graceful, schema-validated loading and inference for Phase 4A artifacts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import joblib

from src.features.models import FeatureObject
from src.ingestion.zeek_websocket import DNSQueryObservation
from src.ml.models import MLResult
from src.ml.schema import FAMILY_FEATURES, schema_manifest, vectorize
from src.ml.training_data import normalize_domain


class MLInferenceEngine:
    """Load independent models; one missing/bad artifact disables only that model."""

    def __init__(self, model_dir: Path | None = None) -> None:
        self.model_dir = model_dir or Path(__file__).resolve().parents[2] / "models" / "phase4a"
        self._models: dict[str, dict[str, Any]] = {}
        self.disabled_models: dict[str, str] = {}
        for family in (*FAMILY_FEATURES, "dga"):
            self._load(family)

    @property
    def loaded_families(self) -> tuple[str, ...]:
        return tuple(sorted(self._models))

    def infer_feature(self, family: str, feature: FeatureObject) -> MLResult | None:
        bundle = self._models.get(family)
        if bundle is None:
            return None
        values, raw = vectorize(family, feature)
        model = bundle["model"]
        probabilities = model.predict_proba([values])[0]
        best = max(range(len(probabilities)), key=probabilities.__getitem__)
        return MLResult(
            bundle["model_name"], bundle["model_version"], family,
            feature.subject, feature.timestamp, str(model.classes_[best]),
            float(probabilities[best]), raw,
        )

    def infer_dga(self, observation: DNSQueryObservation) -> MLResult | None:
        bundle = self._models.get("dga")
        if bundle is None:
            return None
        normalized = normalize_domain(observation.query)
        if not normalized:
            return None
        model = bundle["model"]
        probabilities = model.predict_proba([normalized])[0]
        best = max(range(len(probabilities)), key=probabilities.__getitem__)
        return MLResult(
            bundle["model_name"], bundle["model_version"], "dga",
            f"{observation.source_ip}:{normalized}", observation.event_time,
            str(model.classes_[best]), float(probabilities[best]),
            {"normalized_dns_query": normalized},
        )

    def _load(self, family: str) -> None:
        artifact = self.model_dir / f"{family}.joblib"
        manifest_path = self.model_dir / f"{family}.manifest.json"
        try:
            if not artifact.is_file() or not manifest_path.is_file():
                raise FileNotFoundError("artifact or manifest is absent")
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            bundle = joblib.load(artifact)
            if family == "dga":
                expected_hash = hashlib.sha256(
                    json.dumps({k: v for k, v in manifest.items() if k != "schema_sha256"}, sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest()
                vocabulary = bundle["model"].named_steps["tfidf"].get_feature_names_out().tolist()
                if vocabulary != manifest.get("feature_names"):
                    raise ValueError("DGA TF-IDF vocabulary differs from manifest")
            else:
                expected = schema_manifest(family)
                if manifest.get("raw_feature_names") != expected["raw_feature_names"]:
                    raise ValueError("runtime raw feature order differs from manifest")
                if manifest.get("expanded_feature_names") != expected["expanded_feature_names"]:
                    raise ValueError("runtime expanded feature order differs from manifest")
                if manifest.get("schema_sha256") != expected["schema_sha256"]:
                    raise ValueError("runtime feature schema hash differs from manifest")
                if int(bundle["model"].n_features_in_) != len(expected["expanded_feature_names"]):
                    raise ValueError("artifact input width differs from runtime schema")
            if family == "dga" and manifest.get("schema_sha256") != expected_hash:
                raise ValueError("manifest schema checksum is invalid")
            if bundle.get("schema_sha256") != manifest.get("schema_sha256"):
                raise ValueError("artifact schema checksum differs from manifest")
            if bundle.get("family") != family:
                raise ValueError("artifact family differs from filename")
            if bundle.get("model_name") != manifest.get("model_name"):
                raise ValueError("artifact model name differs from manifest")
            if bundle.get("model_version") != manifest.get("model_version"):
                raise ValueError("artifact model version differs from manifest")
            if bundle["model"].classes_.tolist() != manifest.get("classes"):
                raise ValueError("artifact classes differ from manifest")
            self._models[family] = bundle
        except (
            FileNotFoundError, EOFError, ImportError, AttributeError, KeyError,
            TypeError, ValueError, json.JSONDecodeError, OSError,
        ) as exc:
            self.disabled_models[family] = str(exc)
