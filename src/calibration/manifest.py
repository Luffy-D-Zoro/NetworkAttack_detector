"""Strict manifests for externally stored labelled captures.

Raw datasets are deliberately referenced, never copied into the repository.
The split group is mandatory so windows from one capture/scenario cannot leak
between training, validation, and final test partitions.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal, Mapping

Role = Literal["train", "validation", "test"]
CaptureLabel = Literal["benign", "attack", "background"]
ThreatFamily = Literal["ddos", "scan", "exfil", "beacon", "dns", "encrypted"]


def _time(value: object, path: str) -> datetime:
    if isinstance(value, bool):
        raise ValueError(f"{path} must be an epoch number or ISO-8601 string")
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=UTC)
    if not isinstance(value, str):
        raise ValueError(f"{path} must be an epoch number or ISO-8601 string")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError(f"{path} must include a timezone")
    return parsed.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class AttackInterval:
    start: datetime
    end: datetime

    def __post_init__(self) -> None:
        if self.end <= self.start:
            raise ValueError("attack interval end must follow start")

    def contains(self, timestamp: datetime) -> bool:
        return self.start <= timestamp < self.end


@dataclass(frozen=True, slots=True)
class CaptureSpec:
    capture_id: str
    dataset_name: str
    pcap_path: Path
    label: CaptureLabel
    role: Role
    split_group: str
    threat_family: ThreatFamily | None = None
    intervals: tuple[AttackInterval, ...] = ()
    metadata: Mapping[str, object] = MappingProxyType({})

    def __post_init__(self) -> None:
        if not self.capture_id or not self.dataset_name or not self.split_group:
            raise ValueError("capture_id, dataset_name, and split_group are required")
        if self.label == "attack" and self.threat_family is None:
            raise ValueError("attack captures require threat_family")
        if self.label != "attack" and self.threat_family is not None:
            raise ValueError("only attack captures may set threat_family")
        if self.label == "background" and not bool(self.metadata.get("labels_reliable")):
            raise ValueError("background captures require metadata.labels_reliable=true")
        if self.label not in {"benign", "attack", "background"}:
            raise ValueError("capture label must be benign, attack, or background")
        if self.role not in {"train", "validation", "test"}:
            raise ValueError("capture role must be train, validation, or test")
        if self.threat_family not in {None, "ddos", "scan", "exfil", "beacon", "dns", "encrypted"}:
            raise ValueError("unsupported capture threat_family")

    def active_label(self, timestamp: datetime) -> bool:
        return not self.intervals or any(item.contains(timestamp) for item in self.intervals)


@dataclass(frozen=True, slots=True)
class DatasetManifest:
    schema_version: int
    name: str
    captures: tuple[CaptureSpec, ...]
    source_url: str | None = None
    citation: str | None = None

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError("unsupported dataset manifest schema_version")
        if not self.name or not self.captures:
            raise ValueError("manifest name and captures are required")
        identifiers = [item.capture_id for item in self.captures]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("capture_id values must be unique")
        roles_by_group: dict[str, set[str]] = {}
        for capture in self.captures:
            roles_by_group.setdefault(capture.split_group, set()).add(capture.role)
        leaking = {group: roles for group, roles in roles_by_group.items() if len(roles) > 1}
        if leaking:
            raise ValueError(f"split groups appear in multiple roles: {leaking}")


def load_manifest(path: Path) -> DatasetManifest:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("dataset manifest must be a JSON object")
    allowed = {"schema_version", "name", "source_url", "citation", "captures"}
    if set(document) - allowed:
        raise ValueError(f"unknown manifest keys: {sorted(set(document) - allowed)}")
    raw_captures = document.get("captures")
    if not isinstance(raw_captures, list):
        raise ValueError("captures must be a list")
    captures: list[CaptureSpec] = []
    root = path.resolve().parent
    for index, raw in enumerate(raw_captures):
        if not isinstance(raw, dict):
            raise ValueError(f"captures[{index}] must be an object")
        allowed_capture = {
            "capture_id", "dataset_name", "pcap_path", "label", "role",
            "split_group", "threat_family", "attack_intervals", "metadata",
        }
        if set(raw) - allowed_capture:
            raise ValueError(
                f"unknown captures[{index}] keys: {sorted(set(raw) - allowed_capture)}"
            )
        pcap = Path(str(raw["pcap_path"])).expanduser()
        if not pcap.is_absolute():
            pcap = (root / pcap).resolve()
        intervals_raw = raw.get("attack_intervals", [])
        if not isinstance(intervals_raw, list):
            raise ValueError(f"captures[{index}].attack_intervals must be a list")
        intervals = tuple(
            AttackInterval(
                _time(value["start"], f"captures[{index}].attack_intervals.start"),
                _time(value["end"], f"captures[{index}].attack_intervals.end"),
            )
            for value in intervals_raw
        )
        metadata = raw.get("metadata", {})
        if not isinstance(metadata, dict):
            raise ValueError(f"captures[{index}].metadata must be an object")
        captures.append(CaptureSpec(
            capture_id=str(raw["capture_id"]),
            dataset_name=str(raw.get("dataset_name", document.get("name", ""))),
            pcap_path=pcap,
            label=raw["label"],
            role=raw["role"],
            split_group=str(raw["split_group"]),
            threat_family=raw.get("threat_family"),
            intervals=intervals,
            metadata=MappingProxyType(dict(metadata)),
        ))
    return DatasetManifest(
        schema_version=int(document.get("schema_version", 0)),
        name=str(document.get("name", "")),
        captures=tuple(captures),
        source_url=(str(document["source_url"]) if document.get("source_url") else None),
        citation=(str(document["citation"]) if document.get("citation") else None),
    )
