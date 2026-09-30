# Project Handoff

## Current Phase

Phase 4 — implementation block B complete

Implemented checkpoints:

- Zeek live-monitoring foundation.
- Real-time Zeek-to-Python WebSocket transport.
- Cumulative snapshot adaptation into directional FlowState management,
  inactivity expiration, and active-flow inspection.
- Phase 2 state architecture design for DDoS, scan, beacon, DNS, exfiltration,
  and encrypted-traffic state.
- Strict multi-event WebSocket dispatch, directional connection lifecycle
  events, semantic TCP signals, bounded window primitives, and the DDoS/scan
  state managers defined for Phase 2 block A.
- Directional Exfil state and bounded timing/size Beacon state defined for
  Phase 2 block B.
- Immediate/final DNS metadata transport, offline-PSL DNS state, encrypted-
  protocol metadata transport, and bounded encrypted-session state defined for
  Phase 2 block C.
- Separate deterministic feature extraction, explainable prototype rule
  detectors, and periodic evaluation for DDoS, scan, exfiltration, and
  beaconing in Phase 3 block A.
- Read-only DNS and encrypted-traffic feature extraction, explainable
  multi-indicator prototype detectors, and periodic evaluation integration in
  Phase 3 block B.
- Reproducible synthetic/lab training, persisted schema manifests and model
  artifacts, and independent runtime ML inference for DDoS, scan,
  exfiltration, beaconing, and DNS DGA classification in Phase 4A.
- Transparent rule/ML fusion, canonical structured alerts, bounded cooldown
  suppression, and retained final-alert SQLite storage in Phase 4B.

Phase 1 is accepted and working on the live interface. Phase 2 state
implementation blocks A, B, and C are implemented and automated-test/PCAP
verified. Phase 3 blocks A and B are implemented and verified, covering all
six state families. Phase 4A ML and Phase 4B alerting are implemented and
verified. Anomaly detection, additional ML, and dashboard work have not
started.

## Current Status

The current streaming code path is:

```text
live Zeek
  → cumulative flow_snapshot + semantic TCP/DNS/TLS/DTLS/QUIC events
  → loopback WebSocket
  → strict common-envelope dispatch and event-specific validation
  → cumulative/lifecycle adapter
      ├─ directional deltas → FlowManager + DDoSStateManager
      │                        + ExfilStateManager + BeaconStateManager
      │                        + EncryptedStateManager for identified UIDs
      └─ start/final events → DDoSStateManager + ScanStateManager
                               + BeaconStateManager
  → deduplicated TCP signals → DDoSStateManager + ScanStateManager
  → immediate/final DNS observations → DNSStateManager
  → encrypted identification/metadata + final snapshots
      → EncryptedStateManager
  → periodic bounded-state cleanup and active-flow inspection
  → configurable periodic evaluation (not per update)
      → read-only DDoS/Scan/Exfil/Beacon/DNS/Encrypted feature extraction
      → family-specific explainable prototype rule detector
      → internal DetectorResult
      → schema-validated per-family Random Forest inference
      → independent MLResult
  → each normalized DNS query → character n-gram DGA inference → MLResult
  → transparent family/subject/time-compatible fusion
  → canonical StructuredAlert
  → bounded cooldown suppression
  → SQLite final-alert repository
```

The live Zeek → WebSocket → Python transport was manually runtime-verified on
`wlo1` with Zeek 8.0.6. Real validated JSON `flow_snapshot` events were
observed continuously. The earlier live Zeek check also produced `conn.log`,
`dns.log`, `ssl.log`, `quic.log`, and other standard logs from real traffic.

The complete 120-test suite passes, including real Zeek 8.0.6 DNS and TLS test-
PCAP → loopback WebSocket → strict dispatcher → coordinator integration tests,
plus the prior flow/TCP integration through FlowManager and the Block A/B
state managers and all Phase 3 block A/B deterministic detector scenarios. The
complete Phase 1 pipeline remains accepted and working on the live interface.
The state/detector path has not received a separate live-`wlo1` run; it is
automated-test and PCAP verified.

The complete Phase 2 state architecture is documented in
[`PHASE2_STATE_DESIGN.md`](PHASE2_STATE_DESIGN.md). It defines exact keys,
inputs, stored fields, bounded rolling representations, update and expiration
behavior, future features, unidirectional behavior, complexity, minimal new
Zeek signals, streaming fan-out, and implementation order for all six states.

All six designed state managers now exist: `DDoSStateManager`,
`ScanStateManager`, `ExfilStateManager`, `BeaconStateManager`,
`DNSStateManager`, and `EncryptedStateManager`. All six have deterministic
feature extractors and prototype rule detectors. Their `DetectorResult` values
and Phase 4A `MLResult` values remain available as independent internal
evaluations. Phase 4B can fuse compatible behavioral results into final
`StructuredAlert` values and persist only accepted alerts. No anomaly detector
or dashboard exists.

## Architecture Decisions Made

- Preserve the directional five-tuple exactly as `(src_ip, src_port, dst_ip,
  dst_port, protocol)`; reverse directions are distinct dictionary keys.
- Keep the transport decoder in `src/ingestion/zeek_websocket.py` separate
  from the adapter and Flow Manager.
- Correlate cumulative counters by Zeek UID and directional `FlowKey`. This
  allows a `connection_flipped` event to swap Zeek roles without swapping the
  underlying network directions.
- Derive `packet_delta` and `byte_delta` from the previous cumulative value.
  Duplicate or unchanged snapshots emit no update.
- Use Zeek's cumulative IP-byte counters for `FlowState.byte_count`; payload
  counters remain available in the transport snapshot but are not duplicated
  in compact flow state.
- Treat a counter regression as a reset: replace that direction's baseline and
  emit no delta for the regressed observation. This prevents negative or
  fabricated traffic.
- Retain final UID baselines until configurable correlation expiration so
  duplicate final snapshots remain idempotent. Final traffic is applied, but
  the FlowState remains inspectable until normal inactivity expiration.
- Ignore snapshots older than the latest observation for that UID so late
  delivery cannot roll cumulative baselines backward.
- Retain at most two compact directional counter baselines per active Zeek UID
  and expire stale UID correlations. Never retain raw snapshots or packets.
- Maintain active flows in a Python dictionary keyed by `FlowKey`; cleanup
  scans occur only after the configurable cleanup interval.
- Use event time from validated Zeek snapshots for state timestamps and
  expiration decisions.
- Keep standard Zeek logs for later protocol enrichment. They are not treated
  as a per-packet live feed.
- Continue using the loopback WebSocket defaults `127.0.0.1:9997` and
  `sih/flow/v1`, with configurable overrides.
- Parse the Broker/WebSocket event envelope once and strictly dispatch known
  event names. `iter_snapshots()` remains a compatibility wrapper that filters
  other valid event types rather than rejecting them.
- Derive one `DirectionalConnectionEvent(start)` per `(Zeek UID, FlowKey)`
  after first positive traffic and one `final` per observed direction. Reuse
  the adapter baseline for duplicate, reset, and role-flip safety.
- Publish semantic TCP signals only from `new_connection`,
  `connection_established`, `connection_attempt`, `connection_rejected`, and
  `connection_reset`. No `connection_SYN_packet` or generic packet hook is
  enabled; `syn_start` is a unique connection-level observation.
- Deduplicate TCP signals by `(zeek_uid, kind, actor_role)` in a time-and-count
  bounded map. Its capacity evictions are operational telemetry, not detector
  features.
- Fan validated objects directly to interested managers in one synchronous
  coordinator. No event bus, queue framework, or FlowManager dictionary scan
  is used.
- Key DDoS state by destination IP and scan state by observed source IP. Both
  use manager-specific event-time bucket windows and configurable caps.
- Retain known bounded-map keys after saturation and aggregate unseen-key
  values into explicit overflow fields. Cardinality sets retain stable
  BLAKE2b-128 digests rather than raw high-cardinality values.
- Enforce a configurable LRU cap on each top-level state table and expose
  capacity evictions separately from state features.
- Key Exfil state by directional `(src_ip, dst_ip)`. Ports and protocols are
  bucket dimensions, and an optional reverse-key lookup never merges state.
- Key Beacon state by `(src_ip, dst_ip, dst_port, protocol)`, deliberately
  excluding source port so changing ephemeral ports share one timing pattern.
- Store Beacon timing as three independently time-and-count-bounded ordered
  deques: connection starts, completed activity episodes, and completed
  connection summaries. A separate current aggregate episode groups positive
  deltas using a configurable gap.
- Handle rare in-horizon late Beacon observations by ordered insertion and
  episode merging in O(sample cap); ignore events older than the configured
  horizon. Normal in-order update and expiry remain amortized O(1).
- Publish DNS queries immediately from `dns_request` and finalized outcomes
  from `DNS::log_dns`; never tail `dns.log` and never count a result as another
  query. Optional result values use explicit presence bits.
- Group DNS state by source IP with capped registrable-domain subwindows. Use
  `tldextract==5.3.2` only with its packaged PSL snapshot, network URLs and
  external cache disabled, and private PSL domains enabled.
- Publish encrypted identification from `ssl_client_hello` or the first QUIC
  Initial and metadata from `SSL::log_ssl`/`QUIC::log_quic`. Keep nullable
  fields explicit, distinguish TLS/DTLS/QUIC, and do not invent JA3/JA4 data.
- Key encrypted state by `(client_ip, server_ip, server_port, ip_protocol,
  security_family)`. Route flow deltas only after bounded UID identification;
  reconcile pre-identification traffic from the final cumulative snapshot.
- Retain explicit observed-direction availability. Completed encrypted
  sessions remain UID-deduplicated during a short grace and all buckets,
  routes, active sessions, samples, categories, and top-level keys are capped.
- Keep state managers detector-neutral. Feature extractors read bounded state
  without mutating it, and all rule thresholds live in immutable detector
  configuration objects.
- Preserve unavailable statistics as `None` rather than fabricating zeroes.
  Saturation flags remain visible so cardinality-derived evidence can be
  identified as lower-confidence.
- Use simple multi-signal family-specific rules. DDoS requires a distributed
  observed-source profile, scan requires horizontal or vertical fan-out,
  exfiltration requires both volume and persistence, and beaconing requires
  timing regularity plus additional retained evidence.
- Produce internal `DetectorResult` values with score, disposition
  (`insufficient_data`, `benign_like`, or `suspicious`), evidence, and the
  names of available features. These are not fused and are not alerts.
- Run feature extraction and state-table scans only on a configurable
  event-time evaluation cadence. Streaming state updates remain continuous;
  no detector runs for every packet/update.
- Derive DNS source-wide and bounded per-domain features only from retained
  source/domain buckets. Response-dependent values stay unavailable until
  finalized DNS results exist; a long or high-entropy name alone is not a
  suspicious classification.
- Explain DNS results through separate tunneling-like, DGA-like, and abnormal-
  query indicator groups. Each group requires multiple configurable signals,
  and saturation is reported as lower-confidence evidence.
- Derive encrypted traffic behavior, completed-session statistics, observable
  TLS/DTLS/QUIC metadata distributions, explicit direction availability, SNI
  repetition/missingness, and certificate frequency from bounded state only.
  JA3/JA4 remains unavailable.
- Require both behavioral evidence and protocol-metadata/outcome evidence for
  an encrypted-traffic result to trigger. Encryption or a missing reverse
  direction alone is not suspicious evidence.
- Use four binary `RandomForestClassifier` models rather than forcing
  incompatible DDoS/scan/exfil/beacon feature schemas into one multiclass
  vector. Training scenarios update the production state managers and use the
  production feature extractors.
- Encode every selected flow feature as a value plus an explicit availability
  bit. A missing value uses zero only in its value column while its availability
  bit is zero, so absence is never silently represented as observed zero.
- Classify normalized original DNS query strings with character 3–5 gram
  TF-IDF plus logistic regression. Aggregated DNS hashes are not used to
  reconstruct names.
- Persist exact ordered schema manifests and validate artifact/manifest/runtime
  compatibility before inference. An absent or incompatible model disables
  only that family and produces no fabricated result.
- Run flow ML on the existing periodic evaluator cadence. DGA inference is the
  sole per-query model and runs on the original validated DNS observation.
- Keep rule `DetectorResult` and `MLResult` independent; Phase 4A performs no
  fusion or final confidence calculation.
- Match behavioral rule/ML results only on exact internal family, subject, and
  evaluation timestamp. Normalize ML output to suspicious-class support
  (`confidence` for a suspicious prediction, `1-confidence` for
  `benign_like`) before applying configurable weights.
- Use a configurable equal-weight prototype fusion by default, with a small
  agreement bonus and explicit disagreement reduction. Separate thresholds
  govern fused, rule-only, and discounted ML-only alerts; scores are not
  described as calibrated probabilities.
- Do not fuse source-wide DNS behavior with per-query DGA inference: current
  subjects have different aggregation granularity. Emit compatible endpoint
  context but separate DNS behavioral and DGA alert classes. Encrypted traffic
  remains rule-only because it has no approved ML model.
- Represent final findings with one immutable, JSON-serializable
  `StructuredAlert`; all unavailable endpoint/rule/ML fields remain explicit
  `None` values.
- Suppress repeated alerts with a bounded `(threat_family, subject)` cooldown
  table. Permit an in-cooldown alert only for higher severity or a configured
  material confidence increase; capacity eviction is operational telemetry.
- Persist final alerts only in SQLite through a repository abstraction. Apply
  age/count retention at insertion, expose bounded queries, and catch/report
  storage write failures without stopping the monitoring loop.

## Implemented Components

### `zeek/flow_stream.zeek`

Publishes the flat, version-1 `FlowStream::flow_snapshot` event on open,
periodic update, role flip, and final connection lifecycle events. Each event
contains cumulative counters for both Zeek endpoint roles. It also publishes
the flat version-1 `FlowStream::tcp_connection_signal` event for connection-
level SYN starts, establishment, attempt timeout, rejection, and reset actor.
It additionally publishes flat version-1 immediate/final DNS observations and
TLS/DTLS/QUIC identification/metadata observations with explicit optional-field
presence. Protocol metadata is published before the final flow snapshot. No
per-packet Zeek handler is installed.

### `src/ingestion/zeek_websocket.py`

Subscribes synchronously, validates the common Broker JSON envelope once, and
strictly dispatches immutable `FlowSnapshot`, `TcpConnectionSignal`,
`DNSQueryObservation`, `DNSResultObservation`, or
`EncryptedProtocolObservation` values.
`iter_events()` carries all known events; the compatible `iter_snapshots()`
wrapper still yields only snapshots. Reconnect uses bounded exponential
backoff, and ingestion does not manage state.

### `src/flow/models.py`

Defines immutable directional `FlowKey`, `DirectionalFlowUpdate`, and
`DirectionalConnectionEvent` values, plus mutable compact `FlowState`.
`FlowState` remains unchanged and contains only the key, `first_seen`,
`last_seen`, `packet_count`, and `byte_count`.

### `src/flow/snapshot_adapter.py`

Tracks compact per-UID directional cumulative baselines and emits positive
traffic deltas plus start/final lifecycle events. It handles first
observations, duplicates, reconnect gaps, counter regression, role flips,
final snapshots, UID reuse, out-of-order snapshots, and bounded correlation
expiration. The Phase 1 `adapt()` delta-only API remains available.

### `src/flow/flow_manager.py`

Uses a Python dictionary for constant-time `FlowKey` lookup. It creates or
updates compact states, exposes deterministic active-flow inspection, and
performs configurable inactivity expiration without scanning on every update.

### `src/states/common.py`

Implements the shared event-time `BucketRing`, saturating
`BoundedCounterMap`, stable-digest `BoundedHashSet`, LRU `CappedStateTable`,
time/count-bounded TCP event deduplicator, and timestamp-ordered
`BoundedTimeDeque` used by bounded sample histories. It also exposes stable
digests and explicit LRU eviction needed by bounded protocol joins.

### `src/states/ddos.py`

Implements `DDoSStateManager[dst_ip]` with bounded packet/byte, protocol,
destination-port, observed-source, connection-start, SYN/outcome, and reset-
actor aggregates. Durations and every capacity are explicit configuration.

### `src/states/scan.py`

Implements `ScanStateManager[src_ip]` with bounded connection/protocol starts,
destination-IP, `(protocol, destination-port)`, stable destination-pair hashes,
and TCP semantic outcome aggregates.

### `src/states/exfil.py`

Implements directional `ExfilStateManager[(src_ip, dst_ip)]` with first/last
activity, fixed-duration packet/IP-byte buckets, capped per-protocol totals,
LRU state admission, event-time late-event handling, and optional O(1)
reverse-state lookup without direction merging.

### `src/states/beacon.py`

Implements `BeaconStateManager[(src_ip, dst_ip, dst_port, protocol)]` with
source-port-independent connection starts, gap-grouped activity episodes,
completed directional connection size/duration samples, ordered late-event
handling, three separately capped time horizons, and whole-state expiry.

### `src/states/dns.py`

Implements `DNSStateManager[source_ip]` with source-wide and capped nested
registrable-domain bucket rings, query/name/entropy/category/cardinality
aggregates, finalized response/rcode/RTT/answer aggregates, malformed-name
handling, stable-hash uniqueness, overflow state, bounded deduplication, and
offline packaged-PSL grouping.

### `src/states/encrypted.py`

Implements bounded encrypted service/session state keyed by protocol client,
server, service port, IP protocol, and TLS/DTLS/QUIC family. It correlates UID
identity, directional traffic, metadata distributions, outcomes, final
cumulative reconciliation, explicit direction availability, and time/count-
bounded completed-session samples without decrypting payloads.

### `src/coordinator.py`

Directly fans each validated event to only its interested FlowManager and
state managers, including DNS protocol observations, encrypted UID-routed
deltas, and final encrypted reconciliation. It performs bounded semantic
deduplication and periodic cleanup without scanning FlowManager. It also calls
the Phase 3 evaluator's cheap cadence gate on each event and returns results
only when periodic evaluation is due. When an `AlertService` is supplied, it
also returns the current final-alert batch and persistence-failure count.

### `src/features/models.py` and `src/features/extractors.py`

Define immutable family-specific feature objects and deterministic, read-only
extraction for all six state families. In addition to Block A, DNS extraction
provides source-wide response/name/cardinality features and bounded per-domain
subdomain features; encrypted extraction provides directional traffic,
session, TLS/DTLS/QUIC metadata, SNI, certificate, outcome, and repeated-service
features. Insufficient or unobserved statistics remain explicitly unavailable.

### `src/detectors/models.py` and `src/detectors/rules.py`

Define the common internal `DetectorResult` and immutable prototype threshold
configuration for six explainable statistical/rule detectors. DNS combines
tunneling-like, DGA-like, and abnormal-query indicators. Encrypted traffic
combines behavior with observable protocol metadata/outcomes and never treats
encryption itself as suspicious. Every detector distinguishes insufficient,
benign-like, and suspicious results without asserting a final malicious label.

### `src/detectors/evaluator.py`

Periodically scans all six bounded state tables, extracts features, and
evaluates their matching detector. Its event-time interval is configurable and
results are not retained as an unbounded history. On the same cadence it now
runs available DDoS/scan/exfil/beacon models and exposes independent
`MLResult` values without changing the existing rule-result API.

### `src/ml/`

Defines the immutable `MLResult`, exact flow feature schemas, explicit
missing-value preprocessing, deterministic state-driven flow scenarios,
offline DGA corpus generation, reproducible training, safe schema validation,
graceful per-model disablement, periodic flow inference, and immediate DGA
inference. Joblib loading is restricted by convention to trusted local model
artifacts.

### `src/alerts/models.py` and `src/alerts/fusion.py`

Define the canonical `StructuredAlert`, severity mapping, endpoint attribution,
and transparent fusion configuration. Four behavioral families support exact-
match rule/ML fusion plus rule-only and discounted ML-only paths. DNS behavior,
per-query DGA, and encrypted rule results retain their distinct semantics.

### `src/alerts/suppression.py` and `src/alerts/service.py`

Apply bounded cooldown suppression before persistence. The service emits only
the current batch, stores no alert history in memory, records persistence
failure telemetry, and logs a warning while keeping the pipeline alive when a
repository write fails.

### `src/alerts/storage.py`

Implements the standard-library SQLite repository for inserting final alerts,
recent/since queries, family/severity filters, and configurable maximum-age and
maximum-row retention. The runtime default is `var/alerts/alerts.db`. The
`alerts` table stores the canonical scalar columns plus JSON arrays for
evidence, supporting-feature names, and detection sources; indexes cover
timestamp, `(threat_family, timestamp)`, and `(severity, timestamp)`.

### `scripts/train_models.py`

Regenerates all Phase 4A datasets, five model artifacts, exact manifests, and
held-out synthetic/lab metrics using seed `2404`; it requires no Internet.

### `data/ml/` and `models/phase4a/`

Contain the generated prototype scenario/domain datasets and the trained
artifacts. Each model has a JSON manifest; `validation_metrics.json` records
configuration, sample counts, class distributions, confusion matrices, and
accuracy/precision/recall/F1 with an explicit non-production notice.

### `src/main.py`

Composes the multi-event iterator and direct streaming coordinator while
preserving periodic JSON active-flow inspection and existing runtime options.
It enables the SQLite alert repository by default and prints each newly
accepted structured alert as JSON without retaining an in-memory history.

### `tests/test_flow_manager.py`

Covers new and existing flows, directional role mapping, cumulative deltas,
duplicates, reconnect gaps, regressions, `connection_flipped`, final snapshots,
zero-traffic suppression, out-of-order delivery, flow/baseline expiration,
cleanup cadence, multiple independent keys, and runtime composition.

### `tests/test_zeek_websocket.py`

Retains strict transport tests. Its real Zeek/PCAP WebSocket integration test
passes a snapshot and TCP signal through the dispatcher and coordinator into
FlowManager and all four implemented state managers.

### `tests/test_phase2_block_a.py`

Covers lifecycle idempotence/roles/finalization, strict TCP dispatch,
compatibility filtering, TCP deduplication and capacity telemetry, event-time
buckets and late events, bounded map/set saturation, LRU state eviction,
DDoS/UDP/source aggregation, scan fan-out and horizontal/vertical behavior,
semantic outcomes, unidirectional operation, and cleanup.

### `tests/test_phase2_block_b.py`

Covers Exfil directional/reverse separation, protocol aggregation, sustained
multi-bucket transfer, late events, expiry and state caps; and Beacon source-
port exclusion, contact timing, episode grouping/closure, periodic bursts,
completed connection summaries, duplicate lifecycle suppression, time/count
bounds, late events, unidirectional operation, cleanup, and state caps.

### `tests/test_phase2_block_c.py`

Covers strict DNS/encrypted transport, immediate versus finalized DNS counts,
malformed names, rcodes, uniqueness/entropy, multi-label/private PSL grouping,
domain overflow, late events and cleanup; TLS/QUIC identity, metadata merging,
UID routing, pre/post-identification traffic, directional/final reconciliation,
duplicate suppression, sample/session/state bounds, unidirectional operation,
and real DNS/TLS PCAP → WebSocket → coordinator integration.

### `tests/test_phase3_block_a.py`

Covers single-source high volume versus distributed UDP DDoS-like traffic,
cardinality saturation, TCP outcome/reset and acceleration features,
horizontal/vertical/non-scan service access, burst-only versus sustained
directional exfiltration, missing/observed reverse traffic and directional
ratios, threshold configurability,
insufficient and regular Beacon timing, periodicity/size evidence, and direct
evaluator/coordinator cadence behavior.

### `tests/test_phase3_block_b.py`

Covers benign, tunneling-like, DGA-like, and abnormal DNS patterns; confirms a
single high-entropy signal is insufficient; verifies finalized/missing response
statistics, domain/hash saturation, configurable thresholds, and insufficient
data. It also covers benign TLS service behavior, combined encrypted behavior
and outcome anomalies, missing direction/metadata, QUIC field availability,
category saturation, session statistics, configurable thresholds, insufficient
data, and periodic coordinator evaluation of both new families.

### `tests/test_phase4a_ml.py`

Covers deterministic state-driven data generation, exact schema order,
training/artifact round trips, schema mismatch rejection, missing-model
behavior, flow scenario separation, DGA normalization/inference, confidence
bounds, and periodic evaluator cadence.

### `tests/test_phase4b_alerts.py`

Covers agreement, disagreement, model absence, insufficient rule evidence,
encrypted rule-only alerts, separate DNS/DGA alerts, confidence/severity,
explicit-null JSON, cooldown bypass/suppression/capacity, SQLite reads and
retention, graceful write failure, and coordinator DGA alert integration.

### `scripts/run_zeek_live.sh`

Starts foreground Zeek on a validated interface with the flow-stream policy
loaded and retains standard Zeek logs in a unique run directory. It does not
invoke sudo or alter permissions itself.

### `PHASE2_STATE_DESIGN.md`

Authoritative implementation design for the six planned Phase 2 state systems.
Blocks A, B, and C implement all six assigned state contracts. It remains the
authoritative Phase 2 design.

## Files Added

- `requirements.txt`
- `zeek/flow_stream.zeek`
- `src/ingestion/zeek_websocket.py`
- `src/flow/models.py`
- `src/flow/snapshot_adapter.py`
- `src/flow/flow_manager.py`
- `src/coordinator.py`
- `src/states/__init__.py`
- `src/states/common.py`
- `src/states/ddos.py`
- `src/states/scan.py`
- `src/states/exfil.py`
- `src/states/beacon.py`
- `src/states/dns.py`
- `src/states/encrypted.py`
- `src/features/__init__.py`
- `src/features/models.py`
- `src/features/extractors.py`
- `src/detectors/__init__.py`
- `src/detectors/models.py`
- `src/detectors/rules.py`
- `src/detectors/evaluator.py`
- `src/main.py`
- `tests/test_zeek_websocket.py`
- `tests/test_flow_manager.py`
- `tests/test_phase2_block_a.py`
- `tests/test_phase2_block_b.py`
- `tests/test_phase2_block_c.py`
- `tests/test_phase3_block_a.py`
- `tests/test_phase3_block_b.py`
- `src/ml/__init__.py`
- `src/ml/models.py`
- `src/ml/schema.py`
- `src/ml/training_data.py`
- `src/ml/training.py`
- `src/ml/inference.py`
- `scripts/train_models.py`
- `data/ml/README.md`
- `data/ml/flow_scenarios.jsonl`
- `data/ml/dga_domains.csv`
- `models/phase4a/README.md`
- `models/phase4a/ddos.joblib` and `ddos.manifest.json`
- `models/phase4a/scan.joblib` and `scan.manifest.json`
- `models/phase4a/exfil.joblib` and `exfil.manifest.json`
- `models/phase4a/beacon.joblib` and `beacon.manifest.json`
- `models/phase4a/dga.joblib` and `dga.manifest.json`
- `models/phase4a/validation_metrics.json`
- `tests/test_phase4a_ml.py`
- `src/alerts/__init__.py`
- `src/alerts/models.py`
- `src/alerts/fusion.py`
- `src/alerts/suppression.py`
- `src/alerts/storage.py`
- `src/alerts/service.py`
- `tests/test_phase4b_alerts.py`
- `PHASE2_STATE_DESIGN.md`

## Files Modified in the Latest Checkpoint

- `requirements.txt`
- `src/coordinator.py`
- `src/main.py`
- Phase 4B alert files listed above (added)
- `HANDOFF.md`

## How To Run

Create the local environment once:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Start the current Python pipeline in one terminal:

```bash
source .venv/bin/activate
python -m src.main
```

Start Zeek in a second terminal. Packet capture normally requires root:

```bash
sudo ./scripts/run_zeek_live.sh wlo1
```

The Python process prints a periodic JSON object containing
`active_flow_count` and the compact directional `active_flows` list. The Zeek
runner prints the unique directory containing its standard logs.

The raw validated-event diagnostic receiver remains available and prints all
recognized snapshots, TCP signals, DNS observations, and encrypted-protocol
observations:

```bash
python -m src.ingestion.zeek_websocket
```

Regenerate the Phase 4A prototype datasets, artifacts, manifests, and metrics
offline with the fixed default seed:

```bash
.venv/bin/python scripts/train_models.py
```

Runtime coordinator results now contain independent `detector_results` and
`ml_results`. Flow ML appears only when periodic evaluation is due; a valid
DNS query may produce an immediate DGA `MLResult`. Missing/incompatible models
are recorded in `MLInferenceEngine.disabled_models` and otherwise skipped.

The live runtime additionally prints accepted alerts as JSON and stores them
in `var/alerts/alerts.db`. Override the location with either:

```bash
ALERT_DB_PATH=/path/to/alerts.db python -m src.main
python -m src.main --alert-db /path/to/alerts.db
```

## How To Test

With `requirements.txt` installed:

```bash
.venv/bin/python -m unittest discover -s tests -v
python -m py_compile \
  src/ingestion/zeek_websocket.py \
  src/flow/models.py \
  src/flow/snapshot_adapter.py \
  src/flow/flow_manager.py \
  src/states/common.py \
  src/states/ddos.py \
  src/states/scan.py \
  src/states/exfil.py \
  src/states/beacon.py \
  src/states/dns.py \
  src/states/encrypted.py \
  src/features/models.py \
  src/features/extractors.py \
  src/detectors/models.py \
  src/detectors/rules.py \
  src/detectors/evaluator.py \
  src/coordinator.py \
  src/main.py \
  tests/test_zeek_websocket.py \
  tests/test_flow_manager.py \
  tests/test_phase2_block_a.py \
  tests/test_phase2_block_b.py \
  tests/test_phase2_block_c.py \
  tests/test_phase3_block_a.py \
  tests/test_phase3_block_b.py \
  tests/test_phase4a_ml.py \
  src/ml/models.py \
  src/ml/schema.py \
  src/ml/training_data.py \
  src/ml/training.py \
  src/ml/inference.py \
  scripts/train_models.py \
  src/alerts/models.py \
  src/alerts/fusion.py \
  src/alerts/suppression.py \
  src/alerts/storage.py \
  src/alerts/service.py \
  tests/test_phase4b_alerts.py
.venv/bin/pip check
bash -n scripts/run_zeek_live.sh
zeek -a zeek/flow_stream.zeek
```

Verified on 2026-09-30:

- All 120 tests passed under Python 3.14.7 with `websockets==17.1`,
  `tldextract==5.3.2`, `scikit-learn==1.9.1`, and `joblib==1.6.0`.
- The dedicated actual Zeek 8.0.6 → test PCAP → loopback WebSocket → strict
  multi-event dispatcher → coordinator → FlowManager/DDoS/Scan/Exfil/Beacon
  integration test passed using Zeek's packaged `conn-size.trace` PCAP.
- Dedicated real DNS and TLS PCAP → Zeek 8.0.6 → loopback WebSocket → strict
  dispatcher → coordinator integration tests passed. DNS query/result and
  encrypted identification/final reconciliation reached their managers.
- Offline packaged-PSL behavior was verified for `example.co.uk` and the
  private suffix `github.io`; no network PSL fetch/cache path is configured.
- Python compilation for every source and test module passed.
- Both Python CLI help checks, shell syntax, and `zeek -a` policy validation
  passed.
- Phase 3 blocks A/B synthetic feature/detector and periodic coordinator
  scenarios passed; no live-interface detector result is claimed.
- Phase 4A training completed in `0.729` seconds for the persisted run. Each
  flow family used 96 samples (72 train, 24 validation; balanced classes) and
  achieved synthetic/lab validation accuracy, macro precision, recall, and F1
  of `1.0`. DGA used 480 samples (360 train, 120 validation; balanced classes):
  accuracy `0.9833`, macro precision `0.9839`, macro recall `0.9833`, macro F1
  `0.9833`, confusion matrix `[[60, 0], [2, 58]]` in
  `[benign_like, dga_like]` order. These deliberately separated synthetic/lab
  results are pipeline validation only, never real-world detection accuracy.
- `pip check`, compilation of all Python source/tests/training scripts, Zeek
  policy analysis, Bash and Zsh syntax validation, and all existing
  flow/DNS/TLS PCAP/WebSocket/coordinator integrations passed.
- Phase 4B deterministic tests verified fusion agreement/disagreement,
  rule-only/ML-only paths, DNS/DGA separation, encrypted rule-only alerting,
  JSON serialization, bounded cooldown behavior, SQLite insertion/query/
  filtering/retention, graceful write failure, and coordinator integration.
- Phase 1 is accepted and working on the live `wlo1` interface.
- Phase 2 blocks A, B, and C are automated-test/PCAP verified; a separate manual
  live-interface run for the state-manager path has not been claimed.

## Known Issues / Limitations

- WebSocket publication is bounded live messaging, not durable delivery. A
  reconnecting receiver can recover missed increments when a later cumulative
  snapshot arrives, but cannot recover a connection whose final snapshot was
  entirely missed. Missed semantic TCP signals cannot be reconstructed from a
  later cumulative snapshot.
- Python process restart discards active FlowStates and UID baselines; this
  checkpoint intentionally adds no persistence.
- Counter regression handling is conservative: the regressed observation adds
  no traffic, so traffic between the reset and that observation may be
  undercounted rather than double-counted.
- Expiration and inspection are event-driven. If no snapshots arrive, no timer
  wakes solely to remove state; memory also cannot grow during that idle
  period, and the next snapshot triggers due cleanup.
- The same Zeek connection-level first/last timestamps are used for whichever
  direction has a positive delta because the current event does not carry
  per-direction packet timestamps.
- Final FlowStates are not deleted immediately; they expire through the same
  configurable inactivity rule so short completed flows remain inspectable.
- A one-second Zeek snapshot interval creates work proportional to active
  connections and still requires performance measurement before production.
- The plaintext WebSocket is appropriate only on loopback. Capturing `lo` or
  `any` can also make Zeek observe its own transport traffic.
- DNS/TLS/QUIC metadata uses direct Zeek events, not log tailing. Standard logs
  remain available independently for inspection and enrichment.
- `syn_start` counts unique connection-level initial SYN observations, not SYN
  packets or retransmissions. Exact SYN packet counts remain intentionally
  unavailable because no `connection_SYN_packet` hook is enabled.
- Bounded maps/sets expose saturation and overflow; top-level and dedup LRU
  evictions are operational health counters. Downstream features must not
  present saturated cardinality as exact or treat operational eviction counts
  as attack evidence.
- State cleanup is event-driven. With no incoming event, no cleanup timer
  wakes, but state also cannot grow; the next event runs any due cleanup.
- Beacon histories are intentionally sampled aggregates, not raw deltas or UID
  histories. Count caps can remove the oldest still-in-horizon sample, and
  events older than the Beacon horizon are ignored.
- DNS response-dependent statistics remain unavailable when only queries are
  visible. DoH/other encrypted DNS cannot populate DNSState without forbidden
  decryption and remains encrypted-flow metadata only.
- JA3/JA4 is not emitted because no approved producer exists. The client
  fingerprint distribution therefore remains empty by design.
- WebSocket loss of DNS or encrypted metadata is not durably replayed. Final
  cumulative snapshots can reconcile encrypted traffic counters but cannot
  reconstruct missed protocol attributes or DNS observations.
- Block C has real DNS/TLS PCAP coverage and deterministic QUIC/DTLS schema and
  state coverage; a separate live-interface run and real QUIC PCAP WebSocket
  run have not been claimed.
- Phase 3 rule thresholds are configurable prototype defaults, not calibrated
  scientific boundaries. Detector results are evidence-bearing internal
  evaluations and must not be presented as final alerts or ground truth.
- Cardinality estimates after bounded-map/set saturation are lower-confidence;
  feature objects expose saturation explicitly and detector evidence records
  it where relevant.
- DNS outcomes, RTT, and answer statistics cannot be inferred when finalized
  result observations are absent. DNS name/rate/domain features remain usable
  in query-only visibility.
- Encrypted resumption ratios are unavailable for QUIC and whenever the
  retained state lacks complete TLS/DTLS metadata coverage. Missing traffic
  directions remain explicit and do not become zero-valued ratios.
- All Phase 4A training labels are controlled synthetic/lab scenario labels.
  The artifacts prove real training, persistence, schema validation, and
  inference, but are not calibrated or validated against representative
  production traffic. The high held-out metrics primarily reflect the clear
  generated scenarios and must not be reported as operational accuracy.
- Flow models cover only DDoS, scan, exfiltration, and beaconing. DNS DGA is a
  separate string model. There is no DNS behavior model, encrypted-traffic ML,
  or anomaly detection; Phase 4B fusion therefore applies only to the four
  compatible behavioral families.
- DGA benign-like examples are a small offline curated/generative lab corpus;
  they are not asserted ground truth. Internationalized names receive Python
  lowercase/trailing-dot normalization only; no IDNA conversion is currently
  applied.
- Joblib uses pickle-compatible serialization and therefore model files must
  only come from this trusted project directory. Schema validation detects
  accidental incompatibility but is not a sandbox for hostile artifacts.
- Phase 4B confidence is an explainable prototype score, not a calibrated
  probability or assertion of ground truth. Default fusion weights, bonuses,
  discounts, thresholds, severity bands, and cooldown require real-data
  evaluation before production use.
- Source-wide DNS behavioral findings and per-query DGA predictions are
  intentionally separate alerts because their subjects/timestamps are not
  safely interchangeable. The DGA alert retains the normalized domain and
  observed source when available.
- SQLite is a lightweight local prototype store with synchronous writes and a
  two-second connection timeout. Write failures are logged and counted while
  the alert remains emitted, but failed writes are not durably retried.
- Alert suppression state is process-local and bounded. Restarting Python
  clears cooldown history but not persisted SQLite alerts.

## Current Configuration

- Host: Arch Linux, x86_64.
- Python version tested: 3.14.7.
- Zeek version tested: 8.0.6.
- Runtime-verified interface: `wlo1`.
- WebSocket address: `ws://127.0.0.1:9997/v1/messages/json`.
- Topic: `sih/flow/v1`.
- Zeek snapshot interval: `1sec` by default.
- Flow inactivity timeout: `120` seconds by default.
- Cleanup interval: `5` seconds by default.
- Active-flow inspection interval: `5` seconds by default.
- UID correlation timeout: `300` seconds by default and required to be at
  least the flow inactivity timeout.
- TCP signal deduplication: `600`-second horizon, `100000` entries, and
  `5`-second cleanup cadence by default.
- DDoS state defaults: `60`-second window, `5`-second buckets, `120`-second
  inactivity, `5`-second cleanup, `10000` destinations, `4096` observed
  sources/bucket, `1024` destination ports/bucket, and `32` protocols/bucket.
- Scan state defaults: `300`-second window, `10`-second buckets, `600`-second
  inactivity, `5`-second cleanup, `10000` observed sources, `4096` destination
  IPs/bucket, `4096` protocol/port keys/bucket, `8192` destination-pair
  digests/bucket, and `32` protocols/bucket.
- Exfil state defaults: `3600`-second window, `60`-second buckets,
  `7200`-second inactivity, `30`-second cleanup, `50000` directional IP pairs,
  and `32` protocols/bucket.
- Beacon state defaults: `24`-hour horizon, `60`-second episode gap, `48`-hour
  inactivity, `30`-second cleanup, `50000` keys, and independent `4096`-sample
  caps for episodes, connection starts, and completed connections.
- DNS state defaults: `10`-minute source and `30`-minute domain windows,
  `1`-hour source/domain inactivity, `50000` sources, `1024` domains/source,
  and bounded category/uniqueness/dedup structures. Registrable domains use
  the packaged PSL in `tldextract==5.3.2` with network/cache disabled.
- Encrypted state defaults: `30`-minute buckets window, `2`-hour completed-
  sample horizon, `10`-minute active-session timeout, `1`-hour state
  inactivity, `50000` service keys, `4096` sessions/key, and `200000` UID
  routes, with bounded categories and final deduplication.
- Detector evaluation interval: `10` seconds by default, configurable through
  `StreamingCoordinator` or `PeriodicDetectorEvaluator` construction.
- Phase 4A model directory: `models/phase4a`; training seed: `2404`; flow
  training: 48 examples/class/family; DGA training: 240 examples/class.
- Flow ML: four 120-tree, depth-8, class-balanced `RandomForestClassifier`
  models with explicit availability-bit preprocessing. DGA ML: character
  3–5 gram TF-IDF (maximum 8000 features) plus class-balanced
  `LogisticRegression`.
- Fusion defaults: rule/ML weights `0.5/0.5`, agreement bonus `0.05`,
  disagreement multiplier `0.75`, fused/rule-only thresholds `0.65`,
  discounted ML-only threshold `0.70`, ML-only discount `0.85`, and DGA
  threshold `0.80`.
- Severity defaults: medium at `0.65`, high at `0.80`, critical at `0.95`
  with at least four evidence items; otherwise severity is low.
- Alert suppression defaults: five-minute cooldown, `0.15` material
  confidence increase, and `50000` bounded keys.
- SQLite alert defaults: `var/alerts/alerts.db`, at most `100000` final alerts,
  and 30-day event-time retention.
- All six detector families use immutable configurable prototype defaults in
  their respective `*DetectorConfig` classes.
- Default Zeek output root: `var/zeek/`.
- FlowState byte units: cumulative IP bytes converted to directional deltas.

State window durations and capacities are experimental defaults exposed by
`DDoSStateConfig`, `ScanStateConfig`, `ExfilStateConfig`,
`BeaconStateConfig`, `DNSStateConfig`, `EncryptedStateConfig`, and
`StreamingCoordinator` arguments; they are not
scientific thresholds.

Python timing settings can be overridden with CLI flags or these variables:

```text
FLOW_INACTIVITY_TIMEOUT
FLOW_CLEANUP_INTERVAL
FLOW_INSPECTION_INTERVAL
FLOW_CORRELATION_TIMEOUT
```

Transport settings shared by Zeek and Python remain:

```text
FLOW_STREAM_HOST
FLOW_STREAM_PORT
FLOW_STREAM_TOPIC
FLOW_STREAM_INTERVAL  # Zeek runner only
```

## Next Intended Step

Stop after Phase 4B. The next intended checkpoint requires explicit owner
direction. Do not begin the Streamlit dashboard, anomaly detection, additional
ML, benchmarking, or presentation/documentation cleanup automatically.

## Last Change

Completed Phase 4B: added configurable transparent behavioral rule/ML fusion,
separate DNS behavior/DGA and encrypted rule-only handling, canonical JSON
alerts, bounded cooldown suppression, SQLite final-alert storage/retention,
graceful persistence failure telemetry, and live coordinator/runtime wiring.
Verified all 120 tests, compilation, dependency health, CLI help, Zeek policy
analysis, shell syntax, and all existing real flow/DNS/TLS PCAP → WebSocket →
coordinator integrations. No dashboard, anomaly detection, or additional ML
was implemented.
