# Local Pipeline Benchmark

Run the reproducible benchmark with:

```bash
python scripts/benchmark_pipeline.py --events 10000 --evaluations 1000
```

The current machine-readable result is [`latest.json`](latest.json). The benchmark uses deterministic local metadata and measures these Python-side stages independently:

- strict JSON envelope/schema decoding;
- direct bounded-state fan-out;
- cumulative adapter, state updates, periodic rules/ML orchestration through `StreamingCoordinator`;
- rule feature extraction and detector evaluation;
- one behavioral Random Forest inference.

The result excludes Zeek capture, kernel packet delivery, WebSocket network I/O, and SQLite writes. It is a development microbenchmark, not a production capacity claim. Results depend on CPU, Python build, power state, and other machine load.
