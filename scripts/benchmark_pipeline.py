#!/usr/bin/env python3
"""Reproducible local microbenchmark for the metadata processing pipeline.

This excludes Zeek packet capture, kernel delivery, network I/O, and SQLite.
It measures CPU-side Python stages with deterministic synthetic metadata.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import platform
import statistics
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import perf_counter, perf_counter_ns

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.coordinator import StreamingCoordinator  # noqa: E402
from src.detectors.evaluator import PeriodicDetectorEvaluator  # noqa: E402
from src.flow.flow_manager import FlowManager  # noqa: E402
from src.flow.models import DirectionalFlowUpdate, FlowKey  # noqa: E402
from src.ingestion.zeek_websocket import (  # noqa: E402
    DEFAULT_TOPIC, EVENT_NAME, FlowSnapshot, decode_stream_event,
)
from src.ml.inference import MLInferenceEngine  # noqa: E402
from src.ml.training_data import generate_flow_samples  # noqa: E402
from src.states.beacon import BeaconStateManager  # noqa: E402
from src.states.ddos import DDoSStateManager  # noqa: E402
from src.states.dns import DNSStateManager  # noqa: E402
from src.states.encrypted import EncryptedStateManager  # noqa: E402
from src.states.exfil import ExfilStateManager  # noqa: E402
from src.states.scan import ScanStateManager  # noqa: E402


def _typed(kind: str, data: object) -> dict[str, object]:
    return {"@data-type": kind, "data": data}


def _encoded_snapshot() -> str:
    args = [
        _typed("count", 1), _typed("string", "update"),
        _typed("timestamp", "2026-09-30T12:00:02.000"),
        _typed("string", "BENCH-UID"), _typed("address", "192.0.2.10"),
        _typed("count", 50000), _typed("address", "198.51.100.20"),
        _typed("count", 443), _typed("count", 6),
        _typed("timestamp", "2026-09-30T12:00:00.000"),
        _typed("timestamp", "2026-09-30T12:00:01.500"),
        _typed("count", 3), _typed("count", 240), _typed("count", 156),
        _typed("count", 2), _typed("count", 320), _typed("count", 236),
        _typed("count", 1), _typed("count", 1), _typed("string", "ShADadFf"),
    ]
    metadata = _typed("vector", [_typed("vector", [
        _typed("count", 1),
        _typed("timestamp", "2026-09-30T12:00:02.000"),
    ])])
    event = _typed("vector", [
        _typed("string", EVENT_NAME), _typed("vector", args), metadata,
    ])
    return json.dumps({
        "type": "data-message", "topic": DEFAULT_TOPIC, "@data-type": "vector",
        "data": [_typed("count", 1), _typed("count", 1), event],
    }, separators=(",", ":"))


def _latency_summary(samples_ns: list[int]) -> dict[str, float]:
    ordered = sorted(value / 1_000 for value in samples_ns)
    p95_index = max(0, int(len(ordered) * 0.95) - 1)
    return {
        "mean_us": round(statistics.fmean(ordered), 3),
        "p50_us": round(statistics.median(ordered), 3),
        "p95_us": round(ordered[p95_index], 3),
        "max_us": round(ordered[-1], 3),
    }


def _measure(count: int, operation) -> tuple[float, dict[str, float]]:
    samples: list[int] = []
    started = perf_counter()
    for index in range(count):
        before = perf_counter_ns()
        operation(index)
        samples.append(perf_counter_ns() - before)
    duration = perf_counter() - started
    return duration, _latency_summary(samples)


def _managers():
    return (
        DDoSStateManager(), ScanStateManager(), ExfilStateManager(),
        BeaconStateManager(), DNSStateManager(), EncryptedStateManager(),
    )


def run(event_count: int, evaluation_count: int) -> dict[str, object]:
    if event_count < 100 or evaluation_count < 1:
        raise ValueError("use at least 100 events and one evaluation")

    raw = _encoded_snapshot()
    ingestion_duration, ingestion_latency = _measure(
        event_count, lambda _: decode_stream_event(raw),
    )

    ddos, scan, exfil, beacon, dns, encrypted = _managers()
    base = datetime(2026, 9, 30, tzinfo=UTC)
    source = ipaddress.ip_address("192.0.2.10")
    destination = ipaddress.ip_address("198.51.100.20")

    def update_states(index: int) -> None:
        now = base + timedelta(milliseconds=index)
        update = DirectionalFlowUpdate(
            FlowKey(source, 40_000 + index % 128, destination, 443, 6),
            now, now, 1, 900 + index % 200, f"STATE-{index % 128}",
        )
        ddos.update_flow(update)
        exfil.update_flow(update)
        beacon.update_flow(update)
        encrypted.update_flow(update)

    state_duration, state_latency = _measure(event_count, update_states)

    manager = FlowManager(
        inactivity_timeout=timedelta(minutes=10), cleanup_interval=timedelta(minutes=10),
    )
    full = StreamingCoordinator(
        flow_manager=manager, correlation_timeout=timedelta(minutes=15),
        detector_evaluation_interval=timedelta(seconds=1),
    )
    cumulative: dict[int, int] = {}

    def process_full(index: int) -> None:
        slot = index % 128
        cumulative[slot] = cumulative.get(slot, 0) + 1
        count = cumulative[slot]
        now = base + timedelta(milliseconds=index)
        full.process(FlowSnapshot(
            1, "open" if count == 1 else "update", now, f"FULL-{slot}",
            source, 40_000 + slot, destination, 443, 6, base, now,
            count, count * 900, count * 840, 0, 0, 0, 1, 0, "S",
        ))

    full_duration, full_latency = _measure(event_count, process_full)

    evaluator = PeriodicDetectorEvaluator(
        ddos_manager=ddos, scan_manager=scan, exfil_manager=exfil,
        beacon_manager=beacon, dns_manager=dns, encrypted_manager=encrypted,
        ml_engine=None,
    )
    detector_duration, detector_latency = _measure(
        evaluation_count,
        lambda index: evaluator.evaluate(base + timedelta(seconds=30 + index)),
    )

    engine = MLInferenceEngine(ROOT / "models" / "phase4a")
    samples = generate_flow_samples(seed=2404, samples_per_class=4)
    candidates = [sample for sample in samples if sample.family in engine.loaded_families]
    if not candidates:
        raise RuntimeError("no behavioral ML models are available")
    ml_duration, ml_latency = _measure(
        evaluation_count,
        lambda index: engine.infer_feature(
            candidates[index % len(candidates)].family,
            candidates[index % len(candidates)].feature,
        ),
    )

    def stage(duration: float, count: int, latency: dict[str, float]) -> dict[str, object]:
        return {
            "operations": count, "duration_seconds": round(duration, 6),
            "throughput_per_second": round(count / duration, 1), "latency": latency,
        }

    return {
        "benchmark_version": 1,
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "scope": {
            "zeek_capture_included": False, "websocket_network_io_included": False,
            "sqlite_included": False,
            "note": "Local deterministic Python microbenchmark; not production capacity.",
        },
        "machine": {
            "platform": platform.platform(), "python": platform.python_version(),
            "processor": platform.processor() or "not reported",
            "logical_cpu_count": os.cpu_count(),
        },
        "parameters": {"events": event_count, "evaluations": evaluation_count, "flow_slots": 128},
        "results": {
            "strict_json_ingestion": stage(ingestion_duration, event_count, ingestion_latency),
            "state_fanout": stage(state_duration, event_count, state_latency),
            "full_coordinator": stage(full_duration, event_count, full_latency),
            "rule_detector_evaluation": stage(detector_duration, evaluation_count, detector_latency),
            "ml_inference": stage(ml_duration, evaluation_count, ml_latency),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=int, default=10_000)
    parser.add_argument("--evaluations", type=int, default=1_000)
    parser.add_argument("--output", type=Path, default=ROOT / "benchmarks" / "latest.json")
    args = parser.parse_args()
    result = run(args.events, args.evaluations)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
