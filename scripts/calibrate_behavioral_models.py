#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.calibration.training import load_feature_rows, train_behavioral_family


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("family", choices=("ddos", "scan", "exfil", "beacon"))
    parser.add_argument("cache", nargs="+", type=Path)
    parser.add_argument("--output", type=Path, default=ROOT / "models/calibrated")
    parser.add_argument("--seed", type=int, default=2404)
    args = parser.parse_args()
    rows = load_feature_rows(args.cache, args.family)
    result = train_behavioral_family(
        family=args.family, rows=rows, output_dir=args.output, seed=args.seed
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
