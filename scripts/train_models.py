#!/usr/bin/env python3
"""Train every Phase 4A prototype model reproducibly without network access."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.ml.training import train_all  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, default=2404)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "models" / "phase4a")
    parser.add_argument("--data-dir", type=Path, default=ROOT / "data" / "ml")
    args = parser.parse_args()
    summary = train_all(output_dir=args.output_dir, data_dir=args.data_dir, seed=args.seed)
    print(json.dumps({
        "training_seconds": summary["training_seconds"],
        "flow_samples": summary["flow_samples"],
        "dga_samples": summary["dga_samples"],
        "models": {name: details["metrics"] for name, details in summary["models"].items()},
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
