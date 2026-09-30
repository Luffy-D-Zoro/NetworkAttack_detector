"""Reproducible lab scenarios that exercise the real state/feature pipeline.

These samples are deliberately synthetic prototype data.  They are useful for
validating end-to-end ML mechanics, not for claiming real-world accuracy.
"""

from __future__ import annotations

import ipaddress
import random
import string
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from src.features.extractors import (
    BeaconFeatureExtractor, DDoSFeatureExtractor, ExfilFeatureExtractor, ScanFeatureExtractor,
)
from src.features.models import FeatureObject
from src.flow.models import DirectionalConnectionEvent, DirectionalFlowUpdate, FlowKey
from src.states.beacon import BeaconStateConfig, BeaconStateManager
from src.states.ddos import DDoSStateConfig, DDoSStateManager
from src.states.exfil import ExfilStateConfig, ExfilStateManager
from src.states.scan import ScanStateConfig, ScanStateManager

BASE = datetime(2026, 1, 1, tzinfo=UTC)


@dataclass(frozen=True, slots=True)
class FlowTrainingSample:
    family: str
    label: str
    scenario_id: str
    feature: FeatureObject


def _ip(base: str, offset: int = 0):
    return ipaddress.ip_address(int(ipaddress.ip_address(base)) + offset)


def _key(src, dst, src_port: int, dst_port: int, protocol: int) -> FlowKey:
    return FlowKey(src, src_port, dst, dst_port, protocol)


def _update(key: FlowKey, at: float, packets: int, size: int, uid: str) -> DirectionalFlowUpdate:
    stamp = BASE + timedelta(seconds=at)
    return DirectionalFlowUpdate(key, stamp, stamp, packets, size, uid)


def _connection(key: FlowKey, at: float, uid: str, *, kind: str = "start", first: float | None = None, packets: int = 1, size: int = 80) -> DirectionalConnectionEvent:
    first_at = at if first is None else first
    return DirectionalConnectionEvent(
        1, kind, BASE + timedelta(seconds=at), uid, key, "originator",
        BASE + timedelta(seconds=first_at), BASE + timedelta(seconds=at), packets, size,
    )


def generate_flow_samples(*, seed: int = 2404, samples_per_class: int = 48) -> tuple[FlowTrainingSample, ...]:
    """Generate balanced samples by updating the production state managers."""

    rng = random.Random(seed)
    samples: list[FlowTrainingSample] = []
    for family in ("ddos", "scan", "exfil", "beacon"):
        for malicious in (False, True):
            for index in range(samples_per_class):
                feature = _GENERATORS[family](rng, malicious, index)
                label = f"{family}_like" if malicious else "benign_like"
                samples.append(FlowTrainingSample(family, label, f"{family}-{int(malicious)}-{index:03d}", feature))
    return tuple(samples)


def _ddos(rng: random.Random, malicious: bool, index: int) -> FeatureObject:
    config = DDoSStateConfig(window=timedelta(seconds=60), bucket_width=timedelta(seconds=5))
    manager = DDoSStateManager(config)
    dst = _ip("198.51.100.10", index % 20)
    source_count = rng.randint(28, 65) if malicious else rng.randint(1, 5)
    for source_index in range(source_count):
        protocol = 17 if rng.random() < (0.75 if malicious else 0.25) else 6
        packets = rng.randint(250, 950) if malicious else rng.randint(2, 90)
        if not malicious and source_count == 1 and index % 5 == 0:
            packets = rng.randint(4_000, 9_000)  # benign-like single-source bulk load
        key = _key(_ip("10.0.0.1", source_index), dst, 30_000 + source_index, 443 if protocol == 6 else 53, protocol)
        manager.update_flow(_update(key, rng.uniform(5, 58), packets, packets * rng.randint(300, 1100), f"D{index}-{source_index}"))
        manager.update_connection(_connection(key, rng.uniform(5, 58), f"DC{index}-{source_index}"))
    state = manager.get(dst)
    assert state is not None
    return DDoSFeatureExtractor(config).extract(dst, state, BASE + timedelta(seconds=59))


def _scan(rng: random.Random, malicious: bool, index: int) -> FeatureObject:
    config = ScanStateConfig(window=timedelta(seconds=120), bucket_width=timedelta(seconds=5))
    manager = ScanStateManager(config)
    src = _ip("192.0.2.1", index % 20)
    count = rng.randint(32, 90) if malicious else rng.randint(2, 8)
    vertical = malicious and index % 2 == 1
    for attempt in range(count):
        dst = _ip("198.18.0.1", 0 if vertical else attempt)
        port = (1_000 + attempt) if vertical else (443 if attempt % 3 else 80)
        key = _key(src, dst, 40_000 + attempt, port, 6)
        manager.update_connection(_connection(key, rng.uniform(1, 118), f"S{index}-{attempt}"))
    state = manager.get(src)
    assert state is not None
    return ScanFeatureExtractor(config).extract(src, state, BASE + timedelta(seconds=119))


def _exfil(rng: random.Random, malicious: bool, index: int) -> FeatureObject:
    config = ExfilStateConfig(window=timedelta(minutes=20), bucket_width=timedelta(minutes=1))
    manager = ExfilStateManager(config)
    src, dst = _ip("10.20.0.1", index % 20), _ip("203.0.113.1", index % 20)
    active = rng.randint(12, 19) if malicious else rng.randint(1, 4)
    for bucket in range(active):
        slot = bucket if malicious else rng.randrange(20)
        size = rng.randint(5_000_000, 14_000_000) if malicious else rng.randint(2_000, 500_000)
        packets = max(1, size // rng.randint(700, 1300))
        key = _key(src, dst, 45_000 + bucket, 443, 6)
        manager.update_flow(_update(key, slot * 60 + 30, packets, size, f"X{index}-{bucket}"))
    state_key = (src, dst)
    state = manager.get(state_key)
    assert state is not None
    return ExfilFeatureExtractor(config).extract(state_key, state, manager, BASE + timedelta(minutes=20))


def _beacon(rng: random.Random, malicious: bool, index: int) -> FeatureObject:
    config = BeaconStateConfig(horizon=timedelta(hours=6), episode_gap=timedelta(seconds=8))
    manager = BeaconStateManager(config)
    src, dst = _ip("10.30.0.1", index % 20), _ip("203.0.113.80", index % 20)
    state_key = (src, dst, 443, 6)
    count = rng.randint(10, 22) if malicious else rng.randint(3, 10)
    current = rng.uniform(5, 25)
    for contact in range(count):
        if contact:
            current += (rng.uniform(55, 65) if malicious else rng.uniform(20, 900))
        key = _key(src, dst, 50_000 + contact, 443, 6)
        uid = f"B{index}-{contact}"
        manager.update_connection(_connection(key, current, uid))
        packets = rng.randint(2, 7) if malicious else rng.randint(1, 80)
        size = packets * (rng.randint(90, 160) if malicious else rng.randint(80, 1300))
        manager.update_flow(_update(key, current + 1, packets, size, uid))
        manager.update_connection(_connection(key, current + 2, uid, kind="final", first=current, packets=packets, size=size))
    manager.expire(BASE + timedelta(hours=5, minutes=59))
    state = manager.get(state_key)
    assert state is not None
    return BeaconFeatureExtractor(config).extract(state_key, state, BASE + timedelta(hours=5, minutes=59))


_GENERATORS = {"ddos": _ddos, "scan": _scan, "exfil": _exfil, "beacon": _beacon}


_BENIGN_BASES = (
    "google.com", "microsoft.com", "github.com", "wikipedia.org", "amazon.com",
    "cloudflare.com", "mozilla.org", "python.org", "ubuntu.com", "apple.com",
    "stackoverflow.com", "openstreetmap.org", "debian.org", "ietf.org", "example.net",
    "bbc.co.uk", "gov.uk", "nic.in", "archive.org", "kernel.org",
)


def generate_dga_samples(*, seed: int = 2404, samples_per_class: int = 240) -> tuple[tuple[str, str], ...]:
    rng = random.Random(seed)
    benign: list[str] = []
    prefixes = ("www", "api", "mail", "cdn", "static", "docs", "auth", "download")
    for index in range(samples_per_class):
        base = _BENIGN_BASES[index % len(_BENIGN_BASES)]
        benign.append(base if index < len(_BENIGN_BASES) else f"{prefixes[index % len(prefixes)]}.{base}")
    dga: list[str] = []
    tlds = ("com", "net", "org", "info", "biz")
    alphabet = string.ascii_lowercase + string.digits
    for index in range(samples_per_class):
        length = rng.randint(14, 28)
        token = "".join(rng.choice(alphabet) for _ in range(length))
        if index % 3 == 0:
            token = "".join(rng.choice("bcdfghjklmnpqrstvwxyz") for _ in range(length))
        dga.append(f"{token}.{tlds[index % len(tlds)]}")
    rows = [(normalize_domain(value), "benign_like") for value in benign]
    rows.extend((normalize_domain(value), "dga_like") for value in dga)
    rng.shuffle(rows)
    return tuple(rows)


def normalize_domain(value: str) -> str:
    return value.strip().rstrip(".").lower()
