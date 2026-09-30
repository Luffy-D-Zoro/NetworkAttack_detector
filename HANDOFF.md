# Project Handoff

## Current Phase

Phase 2 — implementation block A complete

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

Phase 1 is accepted and working on the live interface. Phase 2 state
implementation block A is implemented and automated-test verified. No later
Phase 2 state, feature extractor, detector, or later phase has started.

## Current Status

The current streaming code path is:

```text
live Zeek
  → cumulative flow_snapshot + semantic tcp_connection_signal events
  → loopback WebSocket
  → strict common-envelope dispatch and event-specific validation
  → cumulative/lifecycle adapter
      ├─ directional deltas → FlowManager + DDoSStateManager
      └─ start/final events → DDoSStateManager + ScanStateManager
  → deduplicated TCP signals → DDoSStateManager + ScanStateManager
  → periodic bounded-state cleanup and active-flow inspection
```

The live Zeek → WebSocket → Python transport was manually runtime-verified on
`wlo1` with Zeek 8.0.6. Real validated JSON `flow_snapshot` events were
observed continuously. The earlier live Zeek check also produced `conn.log`,
`dns.log`, `ssl.log`, `quic.log`, and other standard logs from real traffic.

The complete 39-test suite passes, including a real Zeek 8.0.6 test-PCAP →
loopback WebSocket → strict dispatcher → coordinator → FlowManager and
DDoS/scan manager integration smoke test. The complete Phase 1 pipeline remains
accepted and working on the live interface. Block A itself has not yet received
a separate live-`wlo1` manual run; it is automated-test and PCAP verified.

The complete Phase 2 state architecture is documented in
[`PHASE2_STATE_DESIGN.md`](PHASE2_STATE_DESIGN.md). It defines exact keys,
inputs, stored fields, bounded rolling representations, update and expiration
behavior, future features, unidirectional behavior, complexity, minimal new
Zeek signals, streaming fan-out, and implementation order for all six states.

`DDoSStateManager` and `ScanStateManager` now exist exactly for block A. No
Beacon, DNS, Exfil, or Encrypted state implementation exists. No detector,
threshold, feature classification, ML, scoring, alerting, database, or
dashboard code exists.

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

## Implemented Components

### `zeek/flow_stream.zeek`

Publishes the flat, version-1 `FlowStream::flow_snapshot` event on open,
periodic update, role flip, and final connection lifecycle events. Each event
contains cumulative counters for both Zeek endpoint roles. It also publishes
the flat version-1 `FlowStream::tcp_connection_signal` event for connection-
level SYN starts, establishment, attempt timeout, rejection, and reset actor.
No per-packet Zeek handler is installed.

### `src/ingestion/zeek_websocket.py`

Subscribes synchronously, validates the common Broker JSON envelope once, and
strictly dispatches immutable `FlowSnapshot` or `TcpConnectionSignal` values.
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
and time/count-bounded TCP event deduplicator.

### `src/states/ddos.py`

Implements `DDoSStateManager[dst_ip]` with bounded packet/byte, protocol,
destination-port, observed-source, connection-start, SYN/outcome, and reset-
actor aggregates. Durations and every capacity are explicit configuration.

### `src/states/scan.py`

Implements `ScanStateManager[src_ip]` with bounded connection/protocol starts,
destination-IP, `(protocol, destination-port)`, stable destination-pair hashes,
and TCP semantic outcome aggregates.

### `src/coordinator.py`

Directly fans each validated snapshot/delta/lifecycle/TCP signal to the
FlowManager and interested state managers. It performs bounded TCP semantic
deduplication and periodic cleanup without scanning FlowManager to update
attack-specific state.

### `src/main.py`

Composes the multi-event iterator and direct streaming coordinator while
preserving periodic JSON active-flow inspection and existing runtime options.

### `tests/test_flow_manager.py`

Covers new and existing flows, directional role mapping, cumulative deltas,
duplicates, reconnect gaps, regressions, `connection_flipped`, final snapshots,
zero-traffic suppression, out-of-order delivery, flow/baseline expiration,
cleanup cadence, multiple independent keys, and runtime composition.

### `tests/test_zeek_websocket.py`

Retains strict transport tests. Its real Zeek/PCAP WebSocket integration test
passes a snapshot and TCP signal through the dispatcher and coordinator into
FlowManager and both block-A state managers.

### `tests/test_phase2_block_a.py`

Covers lifecycle idempotence/roles/finalization, strict TCP dispatch,
compatibility filtering, TCP deduplication and capacity telemetry, event-time
buckets and late events, bounded map/set saturation, LRU state eviction,
DDoS/UDP/source aggregation, scan fan-out and horizontal/vertical behavior,
semantic outcomes, unidirectional operation, and cleanup.

### `scripts/run_zeek_live.sh`

Starts foreground Zeek on a validated interface with the flow-stream policy
loaded and retains standard Zeek logs in a unique run directory. It does not
invoke sudo or alter permissions itself.

### `PHASE2_STATE_DESIGN.md`

Authoritative implementation design for the six planned Phase 2 state systems.
Block A implements only the portions assigned to DDoS and scan; the remaining
state contracts are unchanged and unimplemented.

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
- `src/main.py`
- `tests/test_zeek_websocket.py`
- `tests/test_flow_manager.py`
- `tests/test_phase2_block_a.py`
- `PHASE2_STATE_DESIGN.md`

## Files Modified in the Latest Checkpoint

- `zeek/flow_stream.zeek`
- `src/ingestion/zeek_websocket.py`
- `src/flow/models.py`
- `src/flow/snapshot_adapter.py`
- `src/main.py`
- `tests/test_flow_manager.py`
- `tests/test_zeek_websocket.py`
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

The raw validated-event diagnostic receiver remains available and prints both
snapshots and TCP semantic signals:

```bash
python -m src.ingestion.zeek_websocket
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
  src/coordinator.py \
  src/main.py \
  tests/test_zeek_websocket.py \
  tests/test_flow_manager.py \
  tests/test_phase2_block_a.py
bash -n scripts/run_zeek_live.sh
zeek -a zeek/flow_stream.zeek
```

Verified on 2026-09-30:

- All 39 tests passed under Python 3.14.7 with `websockets==17.1`.
- The dedicated actual Zeek 8.0.6 → test PCAP → loopback WebSocket → strict
  multi-event dispatcher → coordinator → FlowManager/DDoS/Scan integration
  test passed using Zeek's packaged `conn-size.trace` PCAP.
- Python compilation for every source and test module passed.
- Both Python CLI help checks, shell syntax, and `zeek -a` policy validation
  passed.
- Phase 1 is accepted and working on the live `wlo1` interface.
- Phase 2 block A is automated-test/PCAP verified; a separate manual live-
  interface run for the new TCP/state path has not been claimed.

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
- No protocol-log enrichment reader exists yet; `uid` is retained in adapter
  updates for future correlation but is not stored as an unbounded FlowState
  history.
- `syn_start` counts unique connection-level initial SYN observations, not SYN
  packets or retransmissions. Exact SYN packet counts remain intentionally
  unavailable because no `connection_SYN_packet` hook is enabled.
- Bounded maps/sets expose saturation and overflow; top-level and dedup LRU
  evictions are operational health counters. Downstream features must not
  present saturated cardinality as exact or treat operational eviction counts
  as attack evidence.
- State cleanup is event-driven. With no incoming event, no cleanup timer
  wakes, but state also cannot grow; the next event runs any due cleanup.

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
- Default Zeek output root: `var/zeek/`.
- FlowState byte units: cumulative IP bytes converted to directional deltas.

Block-A window durations and capacities are experimental defaults exposed by
`DDoSStateConfig`, `ScanStateConfig`, and `StreamingCoordinator` arguments;
they are not scientific thresholds.

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

Stop after block A. When explicitly requested, the next design-ordered
checkpoint is Phase 2 block B: implement only `ExfilState[(src_ip, dst_ip)]`
from directional deltas using the existing shared bounded primitives and
direct coordinator fan-out.

Do not implement detectors, feature thresholds, ML, alerts, storage, or
dashboard work during Phase 2 state implementation.

## Last Change

Completed Phase 2 implementation block A: strict multi-event dispatch,
directional start/final lifecycle output, the minimal semantic TCP signal
path, shared bounded event-time primitives, direct coordinator fan-out, and
bounded `DDoSStateManager[dst_ip]` / `ScanStateManager[src_ip]`. Verified all
39 tests, Python compilation, CLI loading, Zeek policy parsing, shell syntax,
and the real Zeek/PCAP integration path. No later Phase 2 state or detector was
implemented.
