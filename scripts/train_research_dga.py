#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.ml.dga_research import train_research_dga


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", type=Path, default=ROOT / "data/external/cache/dga_domains_full.csv")
    parser.add_argument("--output", type=Path, default=ROOT / "models/phase4a")
    parser.add_argument("--seed", type=int, default=2404)
    args = parser.parse_args()
    if not args.corpus.is_file():
        parser.error(f"corpus is absent: {args.corpus}")
    print(json.dumps(train_research_dga(corpus_path=args.corpus, output_dir=args.output, seed=args.seed), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
