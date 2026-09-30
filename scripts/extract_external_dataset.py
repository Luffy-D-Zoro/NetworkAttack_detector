#!/usr/bin/env python3
"""Replay manifest PCAPs through Zeek and cache production feature rows."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import timedelta
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.calibration.manifest import load_manifest
from src.calibration.pcap import iter_zeek_pcap_events
from src.calibration.replay import ReplayFeatureCollector, cache_key, write_cache


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--cache-dir", type=Path, default=PROJECT_ROOT / "data/external/cache/features")
    parser.add_argument("--policy", type=Path, default=PROJECT_ROOT / "zeek/flow_stream.zeek")
    parser.add_argument("--interval-seconds", type=float, default=10.0)
    parser.add_argument("--replay-speed", type=float, default=1.0)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    if shutil.which("zeek") is None:
        parser.error("Zeek is not installed or not on PATH")
    interval = timedelta(seconds=args.interval_seconds)
    manifest = load_manifest(args.manifest)
    summary: list[dict[str, object]] = []
    for capture in manifest.captures:
        if not capture.pcap_path.is_file():
            raise FileNotFoundError(
                f"{capture.capture_id}: PCAP is absent: {capture.pcap_path}"
            )
        digest = cache_key(capture, interval=interval)
        output = args.cache_dir / f"{capture.capture_id}-{digest[:16]}.jsonl"
        if output.exists() and not args.force:
            count = sum(1 for _ in output.open(encoding="utf-8"))
            summary.append({"capture_id": capture.capture_id, "rows": count, "cache": str(output), "reused": True})
            continue
        collector = ReplayFeatureCollector(interval=interval)
        events = iter_zeek_pcap_events(
            capture.pcap_path, policy_path=args.policy,
            replay_speed=args.replay_speed,
        )
        count = write_cache(output, collector.iter_collect(events, capture))
        summary.append({"capture_id": capture.capture_id, "rows": count, "cache": str(output), "reused": False})
    print(json.dumps({"dataset": manifest.name, "captures": summary}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
