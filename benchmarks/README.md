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

## Recorded result

The committed run used Python 3.14.7 on Linux x86-64 with 12 logical CPUs,
10,000 synthetic metadata events, 128 rotating flow slots, and 1,000 detector/
ML evaluations.

| Stage | Throughput | Mean latency | p50 | p95 |
|---|---:|---:|---:|---:|
| Strict JSON ingestion | 13,791.0 events/s | 72.219 µs | 71.234 µs | 93.095 µs |
| Direct state fan-out | 39,911.1 updates/s | 24.801 µs | 24.521 µs | 25.899 µs |
| Full coordinator | 16,807.8 events/s | 59.373 µs | 33.063 µs | 39.995 µs |
| Rule-detector evaluation | 10,515.4 evaluations/s | 94.959 µs | 91.307 µs | 115.749 µs |
| Random Forest inference | 235.5 inferences/s | 4,245.569 µs | 4,154.929 µs | 4,831.049 µs |

The full-coordinator stage receives already-decoded `FlowSnapshot` objects,
whereas strict ingestion measures JSON parsing/schema validation separately;
their throughputs must not be added together or interpreted as an end-to-end
capture rate. See `latest.json` for durations, maximum latencies, and exact
scope flags.
