# Passive AI/ML Cyber-Threat Monitor

This hackathon prototype detects suspicious network behavior from a passive, potentially **unidirectional** traffic view. It monitors links and gateways rather than endpoints: it never probes, blocks, injects packets, changes firewall rules, or decrypts TLS/QUIC payloads.

## Architecture

```text
Traffic
  ↓
Zeek
  ↓ loopback WebSocket (strict, versioned events)
streaming flow/protocol states
  ↓
deterministic features
  ├── statistical/rule detection
  └── ML inference
            ↓
         fusion
            ↓
     StructuredAlert
            ↓
         SQLite
            ↓
      Streamlit dashboard
```

Zeek publishes cumulative connection snapshots plus small TCP, DNS, TLS/DTLS, and QUIC metadata events. Python validates every event, derives directional counter deltas, and updates bounded state without storing packets or unlimited history. Detector evaluation is periodic rather than per packet.

## Supported detection families

| Family | Explainable rules/statistics | ML path |
|---|---|---|
| DDoS-like convergence | Rates, volume, distributed observed sources, ports, connection outcomes | Random Forest |
| Horizontal/vertical scanning | Attempts, IP/port/pair fan-out, connection outcomes | Random Forest |
| Exfiltration-like transfer | Directional volume, persistence, burstiness, optional reverse ratios | Random Forest |
| Beaconing-like behavior | Contact/episode timing, jitter, periodicity, size consistency | Random Forest |
| DNS abnormal/tunneling-like behavior | Query/result, entropy, length, fan-out, NXDOMAIN/rcode behavior | Per-query DGA classifier |
| Suspicious encrypted traffic | TLS/DTLS/QUIC behavior and observable metadata; no decryption | Rule-only (no fabricated ML score) |

Signals are evidence, not ground truth. Final fusion keeps rule and ML evidence visible and suppresses repeated alerts with bounded cooldown state.

## ML and its limits

Four family-specific `RandomForestClassifier` models use the same production feature extractors as runtime. The DNS DGA model is character n-gram TF-IDF plus `LogisticRegression` over the original normalized query string. Train reproducibly with:

```bash
.venv/bin/python scripts/train_models.py
```

Artifacts and exact schema manifests are in [`models/phase4a`](models/phase4a); generated lab datasets and validation records are in [`data/phase4a`](data/phase4a). Model loading rejects incompatible schemas and degrades gracefully if an artifact is absent.

The training corpus is deterministic **synthetic/lab data**, not representative field ground truth. Its validation metrics—including any perfect scores—only validate pipeline mechanics and scenario separation; they are not real-world accuracy claims and are not evidence of production readiness or calibration.

## Unidirectional design

The directional key remains `(src_ip, src_port, dst_ip, dst_port, protocol)`. Originator and responder counters become separate directional updates and are never silently merged. Detectors remain useful with one visible direction; unavailable reverse traffic is represented as unavailable (`None`/an explicit availability flag), never invented as zero. Zeek UID correlation handles cumulative snapshots, duplicates, flipped connections, resets, and final reconciliation.

## Install

The verified environment uses Python 3.14 and Zeek 8.0.6.

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python scripts/train_models.py   # only needed to regenerate committed artifacts
```

Zeek live capture still needs the normal OS permission for the selected interface. The scripts do not grant capabilities or change system permissions.

## Run the live system

Use three terminals from the repository root:

```bash
# Terminal 1 — receiver, state/detection pipeline, fusion, SQLite
.venv/bin/python -m src.main

# Terminal 2 — Zeek live capture (replace wlo1 if needed)
sudo ./scripts/run_zeek_live.sh wlo1

# Terminal 3 — read-only dashboard
.venv/bin/streamlit run dashboard/app.py
```

The WebSocket defaults are `127.0.0.1:9997`, topic `sih/flow/v1`. Override them with `FLOW_STREAM_HOST`, `FLOW_STREAM_PORT`, and `FLOW_STREAM_TOPIC`. Alerts default to `var/alerts/alerts.db`; both backend and dashboard accept `ALERT_DB_PATH`.

## Safe controlled demo

Populate the same SQLite database with deterministic alerts for every implemented path, without sending traffic to any host:

```bash
.venv/bin/python scripts/generate_demo_alerts.py
.venv/bin/streamlit run dashboard/app.py
```

The demo drives production state, feature, rule, ML, fusion, suppression, and storage components. It produces DDoS-like, scan-like, exfiltration-like, beacon-like, DNS behavioral, DGA, and encrypted rule-only alerts. Demo-only thresholds are explicitly local to the script and do not change runtime defaults.

Scenario provenance:

- **Real PCAP/Zeek based:** automated integration tests replay Zeek's packaged connection, DNS, TLS, and QUIC fixtures through the policy/WebSocket/coordinator path where a fixture is available.
- **Synthetic state-driven:** `generate_demo_alerts.py` exercises all six families safely and writes final alerts for dashboard demonstration.
- **ML test scenarios:** deterministic bounded-state scenarios train/test the four behavioral models; reproducible benign-like and generated DGA-like domain strings train/test the DNS classifier.

This workflow demonstrates software behavior, not a real attack and not operational model validation.

## Dashboard

The dashboard opens SQLite read-only and never modifies detector state. It auto-refreshes and shows overview counts, recent alerts, family/severity charts, an alert timeline, and selectable evidence/model/endpoint details. Set another database if desired:

```bash
ALERT_DB_PATH=/path/to/alerts.db .venv/bin/streamlit run dashboard/app.py
```

## Validation and benchmark

Run all offline checks:

```bash
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m compileall -q src dashboard scripts tests
.venv/bin/pip check
zeek -a zeek/flow_stream.zeek
zsh -n scripts/*.sh
```

The repository includes automated Zeek/PCAP/WebSocket/coordinator tests for flow, TCP semantics, DNS, TLS, and QUIC metadata. Some integration tests skip when the matching system PCAP is unavailable.

Run the local CPU-side benchmark:

```bash
.venv/bin/python scripts/benchmark_pipeline.py --events 10000 --evaluations 1000
```

See [`benchmarks/latest.json`](benchmarks/latest.json) and [`benchmarks/README.md`](benchmarks/README.md). It measures strict event decoding, bounded-state fan-out, full coordinator processing, detector evaluation, and ML inference. Zeek capture, WebSocket network I/O, SQLite, and kernel delivery are explicitly excluded, so these are reproducible development measurements—not production throughput.

## Current limitations

- Models are trained on synthetic/lab scenarios and need compatible real labeled data, threshold tuning, calibration, drift monitoring, and adversarial evaluation.
- The prototype has no anomaly detector; this is intentional for the hackathon scope.
- Observed source IPs are not necessarily true attackers (spoofing is possible), and a destination is not automatically a confirmed victim.
- Passive unidirectional visibility cannot infer missing reverse traffic, payload content, endpoint state, or intent.
- TLS/QUIC is not decrypted; JA3/JA4 is unavailable because no approved producer is present.
- Bounded maps/sets can saturate; features expose saturation rather than pretending exact cardinality.
- SQLite is suitable for this single-host prototype, not a distributed/high-availability deployment.
- Live capture requires Zeek, a suitable interface, traffic, and OS capture permission; the dashboard can only display alerts that meet configured final thresholds.

The authoritative architecture is [`PROJECT_CONTEXT.md`](PROJECT_CONTEXT.md), current implementation status is [`HANDOFF.md`](HANDOFF.md), and Phase 2 state contracts are in [`PHASE2_STATE_DESIGN.md`](PHASE2_STATE_DESIGN.md).
