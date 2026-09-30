"""Exact, versioned feature schemas shared by training and inference."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

from src.features.models import BeaconFeatures, DDoSFeatures, ExfilFeatures, ScanFeatures

SCHEMA_VERSION = 1

FAMILY_FEATURES: dict[str, tuple[str, ...]] = {
    "ddos": (
        "packets_per_second", "bytes_per_second", "connection_starts_per_second",
        "unique_observed_source_estimate", "source_cardinality_saturated",
        "observed_source_entropy", "dominant_source_concentration",
        "udp_packet_fraction", "udp_byte_fraction", "destination_port_concentration",
        "syn_starts_per_second", "establishment_ratio", "rejection_ratio",
        "attempt_timeout_ratio", "reset_from_source_fraction",
        "reset_from_destination_fraction", "recent_packet_rate_acceleration",
    ),
    "scan": (
        "attempts_per_second", "syn_starts_per_second",
        "unique_destination_ip_estimate", "unique_destination_port_estimate",
        "unique_destination_pair_estimate", "destination_ip_saturated",
        "destination_port_saturated", "destination_pair_saturated",
        "ip_fanout_per_second", "port_fanout_per_second", "horizontal_fanout_ratio",
        "vertical_fanout_ratio", "establishment_ratio", "rejection_ratio",
        "no_reply_ratio", "reset_ratio", "total_attempts",
    ),
    "exfil": (
        "bytes_per_second", "packets_per_second", "total_recent_bytes",
        "total_recent_packets", "active_bucket_count", "active_time_fraction",
        "sustained_transfer_duration_seconds", "byte_rate_variance",
        "byte_rate_burstiness", "reverse_observed",
        "forward_to_reverse_byte_ratio", "forward_to_reverse_packet_ratio",
    ),
    "beacon": (
        "contact_count", "contact_frequency_per_second",
        "connection_interarrival_mean_seconds", "connection_interarrival_variance",
        "connection_interarrival_stddev",
        "connection_interarrival_coefficient_of_variation",
        "connection_robust_jitter_seconds", "episode_count",
        "episode_frequency_per_second", "episode_interarrival_mean_seconds",
        "episode_interarrival_coefficient_of_variation", "episode_robust_jitter_seconds",
        "episode_packet_mean", "episode_byte_mean", "completed_connection_count",
        "duration_mean_seconds", "timing_regularity",
    ),
}

FEATURE_TYPES = {
    "ddos": DDoSFeatures,
    "scan": ScanFeatures,
    "exfil": ExfilFeatures,
    "beacon": BeaconFeatures,
}


def expanded_feature_names(family: str) -> tuple[str, ...]:
    names: list[str] = []
    for name in FAMILY_FEATURES[family]:
        names.extend((name, f"{name}__available"))
    return tuple(names)


def raw_feature_values(family: str, feature: object) -> dict[str, float | None]:
    expected = FEATURE_TYPES[family]
    if not isinstance(feature, expected):
        raise TypeError(f"{family} model requires {expected.__name__}")
    values: dict[str, float | None] = {}
    for name in FAMILY_FEATURES[family]:
        value = getattr(feature, name)
        if value is None:
            values[name] = None
        elif isinstance(value, bool):
            values[name] = float(value)
        else:
            values[name] = float(value)
    return values


def vectorize(family: str, feature: object) -> tuple[list[float], dict[str, float | None]]:
    raw = raw_feature_values(family, feature)
    vector: list[float] = []
    for value in raw.values():
        vector.extend((0.0 if value is None else value, 0.0 if value is None else 1.0))
    return vector, raw


def schema_manifest(family: str) -> dict[str, Any]:
    manifest: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "family": family,
        "feature_object": FEATURE_TYPES[family].__name__,
        "raw_feature_names": list(FAMILY_FEATURES[family]),
        "expanded_feature_names": list(expanded_feature_names(family)),
        "missing_value_strategy": "value_zero_plus_explicit_availability_bit",
    }
    manifest["schema_sha256"] = schema_hash(manifest)
    return manifest


def schema_hash(manifest: Mapping[str, Any]) -> str:
    payload = {key: value for key, value in manifest.items() if key != "schema_sha256"}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()
