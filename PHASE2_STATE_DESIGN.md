# Phase 2 Attack-Specific State Design

## 1. Scope and non-goals

This document fixes the state architecture for the six Phase 2 state systems:

- `DDoSState`
- `BeaconState`
- `DNSState`
- `ScanState`
- `ExfilState`
- `EncryptedState`

It is a design only. It does not define detection thresholds, classify traffic
as malicious, select models, or implement any state.

The Phase 1 directional key remains unchanged:

```text
FlowKey = (src_ip, src_port, dst_ip, dst_port, protocol)
```

Attack-specific state does not copy `FlowState`. It consumes new streaming
observations as they are produced and stores only bounded aggregates needed by
its own future feature extractor.

## 2. Facts about the current pipeline

### 2.1 Already available in Python

`DirectionalFlowUpdate` provides:

```text
key                 directional FlowKey
first_seen          Zeek connection first-packet time
last_seen           Zeek connection latest-packet time
packet_delta        positive new directional packet count
byte_delta          positive new directional IP-byte count
zeek_uid            Zeek connection UID
```

The cumulative adapter already suppresses duplicates, zero deltas, negative
deltas, regressions, and out-of-order snapshots. Consequently, state managers
must consume `DirectionalFlowUpdate`; they must not recalculate cumulative
deltas independently.

`FlowSnapshot` additionally provides `kind`, `observed_at`, both endpoint
roles, cumulative packet/IP-byte/payload-byte counters, endpoint state numbers,
and Zeek connection history. It is validated but remains a transport object.

`FlowState` contains only its directional key, first/last seen times, packets,
and IP bytes. Attack-state managers must not poll or scan the FlowManager's
dictionary. A direct point lookup may be introduced for a specific correlated
event if necessary, but the design below does not require routine lookups.

### 2.2 Already available in Zeek but not delivered live to Python

Zeek 8.0.6 exposes semantic TCP events including:

```text
connection_established
connection_attempt       # initial setup received no reply after tcp_attempt_delay
connection_rejected      # responder rejected setup with RST
connection_reset         # an established connection was aborted with RST
```

The current `FlowSnapshot.history` can show whether SYN, SYN-ACK, ACK, FIN, and
RST behavior was observed, and `orig_state`/`resp_state` expose Zeek's endpoint
states. History is intentionally lossy: some symbols occur at most once and
others are logarithmically recorded. It is suitable for a per-connection
presence indicator, not an exact packet/flag count.

Zeek also exposes these protocol records/events:

- `dns_request` and `DNS::log_dns` with query, type/class, response code,
  reply presence, rejection, RTT, and answer counts;
- `ssl_client_hello` and `SSL::log_ssl` with TLS/DTLS version, cipher, curve,
  SNI, ALPN, resumption, alert, establishment, and certificate fingerprints;
- `QUIC::initial_packet` and `QUIC::log_quic` with QUIC version, SNI, client
  protocol/ALPN, and QUIC history.

The standard `dns.log`, `ssl.log`, and `quic.log` files remain useful retained
metadata, but file tailing is not the live state-update path.

### 2.3 Missing from the live Python stream

The current Python stream does not carry:

- precise TCP setup outcomes as semantic events;
- DNS query/result observations;
- TLS/DTLS or QUIC metadata;
- a connection-level start/final observation for each directional UID/key;
- JA3/JA4-style client fingerprints.

These gaps are addressed below without enabling generic packet processing.

## 3. Recommended streaming connection

Use a small in-process coordinator, not a broker or general event bus:

```text
validated FlowSnapshot
        │
        ▼
cumulative/lifecycle adapter
        │
        ├── DirectionalFlowUpdate ──► FlowManager
        │                          ├─► DDoSStateManager
        │                          ├─► BeaconStateManager
        │                          ├─► ExfilStateManager
        │                          └─► EncryptedStateManager (known UID only)
        │
        └── DirectionalConnectionEvent
                                   ├─► DDoSStateManager
                                   ├─► ScanStateManager
                                   └─► BeaconStateManager

known encrypted UID + final FlowSnapshot ─► EncryptedStateManager

Zeek TCP semantic events ─► TcpConnectionSignal
                                   ├─► DDoSStateManager
                                   └─► ScanStateManager

Zeek DNS events ─────────► DNSQueryObservation / DNSResultObservation
                                   └─► DNSStateManager

Zeek TLS/QUIC events ────► EncryptedProtocolObservation
                                   └─► EncryptedStateManager
```

The coordinator calls state-manager methods directly in the same streaming
loop. It does not enqueue or retain events. One input object is passed by
reference to each interested manager and then discarded.

### 3.1 `DirectionalConnectionEvent` derived in Python

The existing cumulative adapter should later emit a second, small output type:

```text
schema_version
kind                 "start" or "final"
event_time
zeek_uid
key                  directional FlowKey
direction_role       originator or responder at emission time
first_seen
last_seen
total_packets        cumulative total for this UID and direction
total_ip_bytes       cumulative total for this UID and direction
```

Rules:

- Emit `start` once for each `(zeek_uid, FlowKey)` when that direction first
  has a positive packet or byte count. Do not create a start for an all-zero
  direction.
- Emit `final` from a final snapshot for each direction with observed traffic.
- A short connection first seen at final may emit `start` followed by `final`
  in the same adapter result.
- Use the adapter's existing UID/directional baselines for idempotence and
  flip-safe mapping. Do not create a second raw-snapshot history.
- Retain the same bounded correlation lifetime already used by the adapter.

Managers that need connection initiation rather than directional activity use
only `direction_role=originator`. Managers such as BeaconState may consume both
roles as independent visible directions. TCP-specific initiation is measured
separately by `syn_start` and is not inferred from responder activity.

This event supplies connection frequency and per-connection final size without
making each attack state deduplicate snapshot kinds independently.

### 3.2 Minimal `TcpConnectionSignal`

Add one flat, versioned Zeek event on the existing loopback WebSocket for:

```text
schema_version
event_time
zeek_uid
kind                 syn_start | established | attempt_timeout | rejected | reset
orig_h
orig_p
resp_h
resp_p
ip_protocol          always TCP (6)
actor_role           orig | resp | unknown; meaningful for reset
```

Production rules:

- `syn_start`: publish once from the existing `new_connection` handler only
  when the first observed TCP state/history clearly shows an originator SYN
  without ACK. This is a unique connection-level indicator, not a SYN packet
  count.
- `established`: publish from `connection_established`.
- `attempt_timeout`: publish from `connection_attempt`.
- `rejected`: publish from `connection_rejected`.
- `reset`: publish from `connection_reset`; determine `actor_role` from the
  endpoint whose state is `TCP_RESET`, or use `unknown` if ambiguous.

The Python decoder strictly validates the schema and a bounded UID/kind/actor
deduplicator suppresses accidental repeats. Endpoint roles are captured at the
semantic event time. The state systems use the originator-to-responder tuple as
the attempted connection direction; reset actor is a separate attribute.

Do **not** enable `connection_SYN_packet` now. Zeek documents it as a low-level,
potentially expensive event generated for every SYN and SYN-ACK. Zeek's
`connection_established` specifically means that a responder SYN-ACK was seen;
the final client ACK may still be absent. Exact SYN
packet/retransmission rates are therefore explicitly unavailable. If later
evaluation proves that unique connection-level SYN starts and semantic
outcomes are insufficient, this selective TCP-only event can be reconsidered
as a measured optimization decision.

### 3.3 Minimal DNS observations

Publish two flat, versioned events using existing Zeek protocol events.

`DNSQueryObservation`, from `dns_request` immediately when the query is seen:

```text
schema_version, event_time, zeek_uid
source_ip, source_port, resolver_ip, resolver_port, ip_protocol
transaction_id, query, qtype, qclass
```

`DNSResultObservation`, from `DNS::log_dns(rec)` as the transaction record is
written or finalized:

```text
schema_version, query_time, result_time, zeek_uid
source_ip, resolver_ip, ip_protocol, transaction_id
query_if_present, saw_reply, rejected
rcode_if_present, rtt_if_present, answer_count_if_present
```

The flat wire event represents every optional value as a typed `has_*` boolean
followed by its typed value slot. The strict decoder maps an unset pair to
`None`; sentinel strings or negative numeric values are not used.

The result event updates outcome statistics only; it must not increment query
frequency a second time. Immediate `dns_request` delivery preserves usefulness
when only the query direction is visible and no response is ever observed.
The protocol ingress deduplicator uses a stable digest of
`(event_kind, uid, transaction_id, normalized_query, query_time)`, bounded by
the DNS result horizon and a configurable maximum entry count.

### 3.4 Minimal encrypted-protocol observations

Publish a strictly validated `EncryptedProtocolObservation` with:

```text
schema_version
kind                 identified | metadata
event_time
zeek_uid
security_family      tls | dtls | quic
client_ip, client_port
server_ip, server_port
ip_protocol
version              optional
cipher               optional
curve                optional
server_name          optional
alpn                  optional
resumed              optional
established          optional
last_alert           optional
server_cert_fingerprint optional
client_fingerprint   optional
```

As with DNS results, each optional wire field uses a `has_*` boolean plus a
typed value slot, and the Python observation exposes `None` when absent. This
keeps the event flat without confusing a legitimate empty/zero value with
missing metadata.

Sources and timing:

- Publish `identified` once at `ssl_client_hello` for TLS/DTLS and once at the
  first `QUIC::initial_packet` for QUIC. This registers the UID before most
  application traffic.
- Publish `metadata` once from `SSL::log_ssl(rec)` or
  `QUIC::log_quic(rec)`. Optional fields retain explicit missingness; empty
  strings must not be treated as actual values.
- Distinguish QUIC from DTLS when SSL events occur on UDP by checking the QUIC
  analyzer/session state.
- Use TLS client/server orientation, not an assumption that the original
  packet direction is always the TLS client.
- `SSL::Info` already exposes the leaf server certificate fingerprint when a
  certificate was observed. Base Zeek 8.0.6 on this host does not provide a
  JA3/JA4 client fingerprint package. `client_fingerprint` therefore remains
  absent until a specific producer and compatibility contract are approved.

Exact field provenance is: TLS/DTLS version, cipher, curve, SNI, ALPN,
resumption, establishment, and alert from `SSL::Info`; leaf certificate
fingerprint from `SSL::Info$cert_chain_fps[0]` when present; QUIC version, SNI,
ALPN/client protocol, and history-derived completion information from
`QUIC::Info`. Fields not provided by a protocol family remain missing rather
than receiving fabricated defaults.

The WebSocket ingestion layer should later parse the common Broker envelope
once and dispatch by event name to strict schema-specific decoders. Continue
to support `iter_snapshots()` as a focused wrapper. A second configurable topic
such as `sih/metadata/v1` may carry TCP/DNS/encrypted observations over the same
loopback WebSocket connection; this is topic separation, not a new broker.

## 4. Common bounded-window rules

### 4.1 Fixed-duration bucket ring

Rate/fan-out states use a dictionary or ring indexed by:

```text
bucket_index = floor(event_time / configured_bucket_width)
```

At most `ceil(configured_window / bucket_width) + 1` buckets exist per state
entry. Late observations still inside the window update their indexed bucket;
observations older than the window are ignored. Bucket width and window length
are configured separately for each state system.

### 4.2 Bounded maps and sets

A `BoundedCounterMap` retains at most a configured number of keys per bucket.
Known keys continue to update. Once full, unseen keys contribute to explicit
`overflow_count`/`overflow_value` fields instead of causing eviction churn.

A `BoundedHashSet` stores fixed-size hashes up to a configured cap and then
increments an overflow counter. Features must expose saturation so a capped
cardinality is never presented as exact.

Where this document says `hash(value)`, use a stable BLAKE2b 128-bit digest of
the normalized value. Do not use Python's process-randomized `hash()` and do
not retain the original high-cardinality string beside the digest.

These caps are memory controls, not detection thresholds.

Every state manager also has a configurable `max_state_entries`. Managers keep
their top-level dictionary in least-recently-updated order. When admitting a
new key at capacity, evict the least recently updated entry and increment an
operational `capacity_evictions` counter. This is O(1), prevents unbounded
high-cardinality growth inside one window, and does not silently present an
evicted entry as complete detector history. The counter is health telemetry,
not a detection feature.

All UID/event deduplication maps are bounded by both a configurable time horizon
and maximum entry count. At capacity they use the same oldest-entry eviction
policy and expose an operational eviction counter.

### 4.3 Cleanup

Bucket eviction and whole-entry expiration run on a configurable periodic
cleanup cadence, not for every observation. Event-driven cleanup is acceptable:
when no events arrive, memory cannot grow, and the next event performs due
cleanup.

## 5. `DDoSState`

### 5.1 State key

```text
DDoSState[dst_ip]
```

The behavior of interest is many observed sources and flows converging on one
destination. Destination port remains a bucket dimension rather than part of
the state key so distributed attacks across one or many services remain visible
at the host level.

### 5.2 Exact inputs

- `DirectionalFlowUpdate.key.src_ip` → observed source IP.
- `DirectionalFlowUpdate.key.dst_ip` → state key.
- `DirectionalFlowUpdate.key.dst_port` → bounded destination-port frequency.
- `DirectionalFlowUpdate.key.protocol` → protocol packet/byte frequency;
  protocol 17 supplies UDP behavior.
- `DirectionalFlowUpdate.packet_delta` and `byte_delta` → volume counters.
- `DirectionalFlowUpdate.last_seen` → bucket event time.
- `DirectionalConnectionEvent(kind=start, direction_role=originator)` → new
  observed connection count and observed source connection frequency.
- `TcpConnectionSignal` → SYN starts, establishment, no-reply attempts,
  rejections, and resets.

It does not read `FlowState`, `conn.log`, DNS, or encrypted metadata.

### 5.3 Exact fields stored

```text
DDoSState:
    last_activity
    buckets: BucketRing[DDoSBucket]

DDoSBucket:
    bucket_start
    packets
    ip_bytes
    connection_starts
    protocol_packets: BoundedCounterMap[protocol, packets]
    protocol_bytes: BoundedCounterMap[protocol, bytes]
    destination_ports: BoundedCounterMap[dst_port, connection_starts]
    observed_sources:
        BoundedCounterMap[src_ip, {packets, ip_bytes, connection_starts}]
    source_overflow_packets
    source_overflow_bytes
    source_overflow_starts
    syn_starts
    tcp_established
    tcp_attempt_timeouts
    tcp_rejected
    tcp_resets_from_source
    tcp_resets_from_destination
    tcp_resets_unknown
```

No packet, snapshot, UID history, or full FlowKey set is stored.

### 5.4 Rolling-window representation

Use short configurable fixed-duration buckets. Source and port maps are capped
inside each bucket. Multiple feature horizons may be computed by summing the
most recent buckets; no global project-wide window is introduced.

### 5.5 Update behavior

- A positive directional delta increments packet/byte totals, protocol totals,
  and the observed-source entry in the destination's current event-time bucket.
- A start event increments connection and destination-port counts.
- A TCP signal increments exactly its semantic counter in the destination
  bucket. `rejected` and `attempt_timeout` are outcomes, not extra starts.
- Duplicate and zero-delta flow information is already suppressed upstream.
  TCP signal duplicates are ignored by the signal deduplicator.

### 5.6 Expiration

Evict buckets once their end time is older than the configured DDoS window.
Remove the entire destination entry when it has no buckets and `last_activity`
is older than a configurable DDoS-state inactivity timeout.

### 5.7 Future features exposed

- packets/sec and IP-bytes/sec;
- directional connection starts/sec;
- approximate unique observed source count plus saturation indicator;
- observed-source packet-frequency entropy, treating overflow as an explicit
  aggregate category;
- concentration of top observed sources;
- protocol distribution and UDP packet/byte share;
- destination-port concentration;
- SYN-start rate;
- establishment, timeout, and rejection ratios;
- reset direction ratios;
- rate acceleration across consecutive buckets.

### 5.8 Unidirectional behavior

Incoming visible traffic alone updates destination rate, volume, UDP share,
source diversity, and SYN starts. Missing replies leave establishment/rejection
features marked unavailable or one-sided; they do not block the other features.
Observed source addresses are never described as verified attackers because
they may be spoofed.

### 5.9 Complexity

Average update time is O(1). Feature extraction is O(number of retained buckets
times configured map caps). Memory is approximately
`O(active_destinations × buckets × (source_cap + port_cap + protocol_cap))`.

## 6. `ScanState`

### 6.1 State key

```text
ScanState[src_ip]
```

Scanning is source-centric fan-out toward many destination IPs, ports, or
destination/port pairs. The key means “activity observed from this source”; it
does not assert that the address is the true scanner.

### 6.2 Exact inputs

- `DirectionalConnectionEvent(kind=start, direction_role=originator)` supplies
  source IP, destination IP, destination port, protocol, UID-deduplicated
  observed connection start, and event time.
- `TcpConnectionSignal` supplies SYN starts and setup/reset outcomes.
- `DirectionalFlowUpdate` and `FlowState` are not needed for the minimal scan
  state; repeated volume updates must not be mistaken for new attempts.

### 6.3 Exact fields stored

```text
ScanState:
    last_activity
    buckets: BucketRing[ScanBucket]

ScanBucket:
    bucket_start
    connection_starts
    protocol_starts: BoundedCounterMap[protocol, starts]
    destination_ips: BoundedCounterMap[dst_ip, starts]
    destination_ports: BoundedCounterMap[(protocol, dst_port), starts]
    destination_pairs: BoundedHashSet[(dst_ip, protocol, dst_port)]
    destination_pair_overflow
    syn_starts
    tcp_established
    tcp_attempt_timeouts
    tcp_rejected
    tcp_resets
```

### 6.4 Rolling-window representation

Use configurable short/medium fixed-duration buckets. Destination maps and
pair hashes are independently capped per bucket.

### 6.5 Update behavior

- On a start event, increment one connection start, protocol count,
  destination-IP count, destination-port count, and destination-pair hash.
- On a TCP signal, increment only the corresponding semantic counter.
- Do not count periodic deltas as attempts. Ignore duplicates upstream.
- UDP and other non-TCP fan-out still enters through connection starts; TCP
  outcome fields remain absent for those protocols.

### 6.6 Expiration

Evict buckets outside the configured scan window. Remove a source entry after
all buckets are empty and it has exceeded the configurable scan-state
inactivity timeout.

### 6.7 Future features exposed

- attempts/sec and SYN starts/sec;
- unique destination-IP, destination-port, and destination-pair estimates with
  saturation indicators;
- IP fan-out rate and port fan-out rate;
- horizontal-scan tendency (many IPs, few ports);
- vertical-scan tendency (few IPs, many ports);
- protocol distribution;
- establishment, rejection, and no-reply ratios;
- sequential growth across buckets.

### 6.8 Unidirectional behavior

One visible outbound direction is sufficient for source fan-out and SYN-start
features. If replies are not visible, outcome ratios are unavailable or
one-sided rather than assumed to be failures. If only the reverse direction is
visible, state still describes the observed source/destination direction and
does not reconstruct an unseen initiator.

### 6.9 Complexity

Average updates are O(1). Memory is approximately
`O(active_sources × buckets × (destination_ip_cap + destination_port_cap + pair_cap))`.

## 7. `BeaconState`

### 7.1 State key

```text
BeaconState[(src_ip, dst_ip, dst_port, protocol)]
```

The source port is intentionally excluded so repeated short connections from
changing ephemeral ports contribute to one communication pattern. Source,
destination service, and transport direction remain explicit.

### 7.2 Exact inputs

- `DirectionalFlowUpdate.last_seen`, packet delta, byte delta, UID, and key
  update activity episodes and episode sizes.
- `DirectionalConnectionEvent(kind=start)` supplies one contact time per UID
  and direction.
- `DirectionalConnectionEvent(kind=final)` supplies final per-connection
  duration, packets, and IP bytes.
- No DNS/TLS payload metadata or reverse direction is required.

### 7.3 Exact fields stored

```text
BeaconState:
    last_activity
    current_episode:
        start_time
        last_time
        packets
        ip_bytes
    episodes: deque[EpisodeSample]
        EpisodeSample = {start_time, last_time, packets, ip_bytes}
    connection_starts: deque[timestamp]
    completed_connections: deque[ConnectionSample]
        ConnectionSample = {end_time, duration, packets, ip_bytes}
```

The coordinator's connection events are already UID-deduplicated, so the state
does not retain an unbounded UID set.

### 7.4 Rolling-window representation

Use timestamp-ordered deques, because periodicity and jitter need individual
intervals rather than coarse bucket totals. Bound every deque by both a
configurable long time horizon and a configurable maximum sample count.

An activity episode groups consecutive positive deltas while the gap since the
previous delta is no greater than a configurable episode-gap value. This keeps
a continuous transfer from creating one “contact” every snapshot interval,
while still allowing periodic bursts inside a long-lived connection to be
observed.

### 7.5 Update behavior

- A start event appends its contact timestamp once.
- A positive flow delta starts, extends, or closes/replaces the current episode
  according to the episode-gap rule and adds its packet/byte deltas.
- A final event appends one completed-connection sample. It may also close the
  current episode when appropriate.
- Duplicate and zero-delta updates are ignored upstream. Out-of-order events
  older than the retained horizon are ignored; in-horizon late samples are
  inserted in timestamp order or buffered for cleanup-safe ordered insertion.

### 7.6 Expiration

Pop deque entries older than the state's configurable beacon horizon and
enforce sample caps after each update/periodic cleanup. Finalize or discard a
stale current episode after the episode gap. Remove the entire key when it has
no current episode or samples and exceeds a configurable state inactivity
timeout.

### 7.7 Future features exposed

- connection inter-arrival mean, variance, standard deviation, coefficient of
  variation, and robust jitter statistics;
- activity-episode inter-arrival equivalents for persistent connections;
- contacts per time unit;
- episode and connection packet/byte mean, variance, and range;
- duration distribution;
- periodicity score or autocorrelation computed later from retained times;
- missed-interval tolerance and long-term regularity.

### 7.8 Unidirectional behavior

Each visible direction has its own key and timing/size sequence. Periodicity
does not require acknowledgements or response bytes. If both directions are
visible, they remain separate states and may be compared later as an optional
feature.

### 7.9 Complexity

In-order updates and expiration are amortized O(1). Rare in-horizon late
insertion is O(sample_cap). Memory is `O(active_beacon_keys × sample_cap)` with
three independently configured, bounded deques.

## 8. `DNSState`

### 8.1 State key

```text
DNSState[source_ip]
```

The source key captures query generation behavior across domains. Each source
entry contains bounded subwindows keyed by registrable/base domain so tunneling
patterns for one parent domain are not diluted by unrelated lookups.

Registrable-domain extraction must use a locally installed, versioned Public
Suffix List implementation. A last-two-label heuristic is not acceptable for
suffixes such as `co.uk`. Use `tldextract` with network suffix-list fetching
and cache lookup disabled:

```python
tldextract.TLDExtract(
    suffix_list_urls=(),
    cache_dir=None,
    fallback_to_snapshot=True,
    include_psl_private_domains=True,
)
```

This forces the packaged PSL snapshot and treats private suffixes such as
`github.io` correctly for tenant-domain grouping. Pin the package version after
confirming Python 3.14 compatibility. Add this dependency only when DNSState is
implemented.

### 8.2 Exact inputs

From `DNSQueryObservation`:

- source IP → state key;
- event time → bucket;
- query string → normalized name, length, labels, registrable domain,
  subdomain portion, and subdomain Shannon entropy computed in Python;
- qtype/qclass → bounded categorical counts;
- UID/transaction ID are transport correlation fields and are not retained as
  an unlimited history.

From `DNSResultObservation`:

- result/query time → matching event-time outcome bucket;
- saw-reply, rejected, rcode, RTT, answer count → result aggregates.

No `FlowState` scan and no `dns.log` tailing is used.

### 8.3 Exact fields stored

```text
DNSState:
    last_activity
    source_buckets: BucketRing[DNSSourceBucket]
    domains: BoundedMap[registrable_domain, DNSDomainWindow]
    domain_overflow: DNSDomainWindow

DNSSourceBucket:
    bucket_start
    query_count
    query_length_sum
    query_length_sum_squares
    max_query_length
    label_count_sum
    malformed_query_count
    qtype_counts: BoundedCounterMap[qtype, count]
    qclass_counts: BoundedCounterMap[qclass, count]
    unique_qname_hashes: BoundedHashSet[hash(normalized_qname)]
    qname_hash_overflow
    unique_base_domain_hashes: BoundedHashSet[hash(registrable_domain)]
    base_domain_hash_overflow
    result_count
    reply_count
    no_reply_count
    rejected_count
    rcode_counts: BoundedCounterMap[rcode, count]
    rtt_sum
    rtt_sum_squares
    rtt_count
    answer_count_sum

DNSDomainWindow:
    last_activity
    buckets: BucketRing[DNSDomainBucket]

DNSDomainBucket:
    bucket_start
    query_count
    subdomain_length_sum
    subdomain_length_sum_squares
    max_subdomain_length
    subdomain_entropy_sum
    subdomain_entropy_sum_squares
    max_subdomain_entropy
    unique_subdomain_hashes: BoundedHashSet[hash(subdomain)]
    subdomain_hash_overflow
    qtype_counts: BoundedCounterMap[qtype, count]
```

Only normalized registrable-domain keys are stored as strings. Full query and
subdomain uniqueness uses fixed-size hashes, not unbounded raw strings.

### 8.4 Rolling-window representation

Use configurable fixed-duration buckets for both source-wide and per-domain
windows. The source and domain horizons may differ. Cap the number of retained
domain entries per source; unseen domains after saturation feed one overflow
window.

### 8.5 Update behavior

- Normalize a query by lowercasing and removing one terminal dot while
  retaining label boundaries. A name is malformed if it is empty, exceeds the
  DNS 255-octet wire-name limit, contains an empty interior label, or contains
  a label over 63 octets. Count the source-wide query and
  `malformed_query_count`, but do not create a per-domain entry for it.
- A query observation increments source and selected domain buckets once.
- A result observation updates only result/reply/rcode/RTT/answer fields; it
  never increments query frequency.
- Duplicate protocol events are rejected by a bounded correlation/dedup layer.
- Missing optional response fields leave their individual aggregates
  unchanged. Missing responses increment `no_reply_count` only when Zeek emits
  a finalized result with `saw_reply=false`, not merely because a reply has not
  arrived yet.

### 8.6 Expiration

Evict source and domain buckets outside their configured horizons. Remove a
domain subwindow when it is empty and inactive; remove the source entry after
its source buckets, domain map, and overflow window are empty and its inactivity
timeout has elapsed.

### 8.7 Future features exposed

- queries/sec;
- query-length and label-count statistics;
- qtype/qclass distribution;
- approximate unique full-query and registrable-domain counts with saturation;
- NXDOMAIN/rcode, rejection, and no-reply ratios when responses are visible;
- RTT and answer-count statistics;
- per-base-domain query frequency;
- subdomain length, entropy, and uniqueness statistics;
- repetition ratio and unique-subdomain growth;
- source-wide domain fan-out suitable for later DGA analysis.

### 8.8 Unidirectional behavior

Visible queries immediately update frequency, name, qtype, entropy, and
uniqueness features even if no response direction exists. Response-dependent
features are explicitly marked unavailable until finalized result data exists.
Encrypted DNS payloads such as DoH cannot populate DNSState and remain visible
only as encrypted flow metadata; no decryption is attempted.

### 8.9 Complexity

Each query costs O(query length) for normalization, PSL lookup, hashing, and
entropy, followed by expected O(1) state updates. Result updates are O(1).
Memory is approximately
`O(active_sources × (source_buckets × source_caps + domain_cap × domain_buckets × subdomain_cap))`.

## 9. `ExfilState`

### 9.1 State key

```text
ExfilState[(src_ip, dst_ip)]
```

The behavior of interest is sustained directional transfer between a source
and destination across ports and protocols. Reverse traffic has the separate
key `(dst_ip, src_ip)` and is never merged.

### 9.2 Exact inputs

- `DirectionalFlowUpdate.src_ip/dst_ip` → state key.
- `packet_delta`, `byte_delta` → directional volume.
- protocol → protocol byte/packet distribution.
- `last_seen` → event-time bucket and last activity.
- Directional connection events and final summaries are not required for the
  minimal state.

It does not scan `FlowState` or require protocol payload metadata.

### 9.3 Exact fields stored

```text
ExfilState:
    first_activity
    last_activity
    buckets: BucketRing[ExfilBucket]

ExfilBucket:
    bucket_start
    packets
    ip_bytes
    protocol_packets: BoundedCounterMap[protocol, packets]
    protocol_bytes: BoundedCounterMap[protocol, bytes]
```

### 9.4 Rolling-window representation

Use medium/long configurable fixed-duration buckets. One maximum retained
horizon can support shorter subwindows by summing recent buckets. It is
independent of the DDoS, scan, and beacon windows.

### 9.5 Update behavior

- Every positive directional delta increments exactly one source/destination
  state and bucket.
- Duplicate and zero deltas are ignored upstream.
- Reverse-direction updates go to the reverse key. They are never applied to
  this state entry.

### 9.6 Expiration

Evict buckets outside the exfiltration horizon. Remove the pair when no buckets
remain and `last_activity` exceeds a configurable pair inactivity timeout.

### 9.7 Future features exposed

- bytes/sec and packets/sec over multiple horizons;
- total directional bytes and packets;
- active-bucket count and active-time fraction;
- sustained-transfer duration from first/last active bucket;
- burstiness and rate variance across buckets;
- protocol byte/packet distribution;
- optional directional byte/packet ratio obtained by O(1) lookup of the
  reverse key when it exists, with an explicit “reverse not observed” value.

### 9.8 Unidirectional behavior

All primary volume, rate, duration, persistence, and burstiness features use
one visible direction. Reverse ratios are optional and never required. The
state does not infer data ownership or label a large transfer as exfiltration.

### 9.9 Complexity

Average update time is O(1). Memory is
`O(active_directional_ip_pairs × retained_buckets × protocol_cap)`.

## 10. `EncryptedState`

### 10.1 State key

```text
EncryptedState[(client_ip, server_ip, server_port, ip_protocol, security_family)]
```

`security_family` is one of `tls`, `dtls`, or `quic`. The client source port is
excluded so repeated encrypted sessions to the same service aggregate despite
ephemeral ports. Client/server roles come from the protocol analyzer, not from
an assumption about packet direction. IP protocol and family distinguish TLS,
DTLS, and QUIC services sharing a port.

### 10.2 Exact inputs

From `EncryptedProtocolObservation`:

- client/server endpoints, IP protocol, and family → state key;
- UID → bounded session correlation;
- event time → metadata/session bucket;
- version, cipher, curve, SNI, ALPN, resumption, establishment, alert,
  certificate fingerprint, and optional client fingerprint → categorical and
  outcome aggregates.

From `DirectionalFlowUpdate` after UID registration:

- key endpoints determine client-to-server versus server-to-client direction;
- packet/byte delta and `last_seen` update traffic buckets and the active
  session accumulator.

From a validated `FlowSnapshot(kind=final)` routed only for an already
identified encrypted UID:

- both directions' exact cumulative packets/IP bytes and connection duration
  finalize the UID's session sample and reconcile traffic missed before
  protocol identification. The snapshot is consumed immediately and never
  retained.

No encrypted payload is retained or decrypted.

### 10.3 Exact fields stored

```text
EncryptedState:
    last_activity
    buckets: BucketRing[EncryptedBucket]
    active_sessions: BoundedMap[zeek_uid, EncryptedSessionAccumulator]
    completed_sessions: deque[EncryptedSessionSample]

EncryptedBucket:
    bucket_start
    session_starts
    metadata_records
    client_to_server_packets
    client_to_server_ip_bytes
    server_to_client_packets
    server_to_client_ip_bytes
    established_count
    failed_or_incomplete_count
    resumed_count
    alert_count
    version_counts: BoundedCounterMap[string, count]
    cipher_counts: BoundedCounterMap[string, count]
    curve_counts: BoundedCounterMap[string, count]
    alpn_counts: BoundedCounterMap[string, count]
    server_name_hashes: BoundedCounterMap[hash(server_name), count]
    server_cert_fingerprints: BoundedCounterMap[string, count]
    client_fingerprints: BoundedCounterMap[string, count]

EncryptedSessionAccumulator:
    zeek_uid
    first_seen
    last_seen
    client_to_server_packets
    client_to_server_ip_bytes
    server_to_client_packets
    server_to_client_ip_bytes
    metadata_seen

EncryptedSessionSample:
    end_time
    duration
    client_to_server_packets
    client_to_server_ip_bytes
    server_to_client_packets
    server_to_client_ip_bytes
    directions_observed_mask
```

Server names are hashed in retained frequency maps to bound string memory.
Version/cipher/curve/ALPN values are length-limited and capped. The client
fingerprint map remains empty until an approved producer exists.

### 10.4 Rolling-window representation

Use configurable fixed-duration buckets for traffic, connection frequency,
outcomes, and categorical distributions. Keep completed session samples in a
deque bounded by both time and count for duration/size distributions. Active
sessions and the global UID-to-encrypted-key routing map are bounded by
inactivity and a configurable cap.

### 10.5 Update behavior

- `identified` registers the UID and creates/increments one session start. A
  repeated identification for the UID merges metadata and does not increment
  the session count again. If bounded-map admission evicts the least recently
  updated session, increment the manager's operational capacity-eviction
  counter; the evicted session does not produce a fabricated completion sample.
- `metadata` updates categorical/outcome counts once per UID. Later enriched
  metadata merges missing fields without recounting unchanged values.
- A flow delta is routed only after its UID is identified. It increments the
  correct directional counters in the state bucket and session accumulator.
- On the final snapshot, use both cumulative directional totals to add
  `max(0, final_total - already_applied)` for each counter, append exactly one
  completed sample, and remove the active accumulator after a short
  duplicate-suppression grace. Zeek publisher priorities must deliver
  TLS/QUIC metadata before the flow final for the same UID; this ordering must
  be covered by integration tests.
- Unknown, duplicate, zero-delta, or schema-invalid observations do not mutate
  state.

### 10.6 Expiration

Evict buckets and completed samples outside their independent configured
horizons. Expire abandoned active sessions and UID routing records after a
configurable timeout. Remove the state entry when it has no buckets, samples,
or active sessions and exceeds its inactivity timeout.

### 10.7 Future features exposed

- encrypted sessions/sec and connection frequency;
- client-to-server and server-to-client packet/byte rates;
- packet/byte directional ratios when both sides are visible;
- session duration and size distributions;
- version, cipher, curve, and ALPN distributions;
- SNI uniqueness/repetition and missing-SNI ratio;
- establishment, resumption, alert, and incomplete ratios;
- server certificate and optional client-fingerprint frequency/novelty;
- timing regularity and repeated-service behavior;
- QUIC/TLS/DTLS family distribution at higher-level aggregations.

### 10.8 Unidirectional behavior

Identification metadata and whichever traffic direction is visible still
populate session frequency, TLS/QUIC attributes, timing, and one-sided size
features. Direction availability is recorded explicitly; an absent reverse
direction is not converted to a zero-byte claim. No feature requires decryption.

### 10.9 Complexity

Metadata and traffic updates are expected O(1). Final reconciliation is O(1)
per direction. Memory is approximately
`O(active_encrypted_keys × (buckets × categorical_caps + session_sample_cap) + active_encrypted_UIDs)`.

## 11. TCP SYN/RST/attempt decision

| Information | Status | Design use |
|---|---|---|
| IP protocol, endpoint tuple, UID | Already available | `FlowSnapshot` / `DirectionalFlowUpdate` |
| Directional packet and IP-byte deltas | Already available | DDoS volume; not attempt count |
| Endpoint TCP state and history | Already available | Validation/fallback presence indicators only |
| One connection-level initial SYN indicator | Derivable cheaply | Publish `syn_start` from `new_connection` when state/history is unambiguous |
| Responder SYN-ACK (“established” in Zeek event terminology) | Exists in Zeek, missing in Python | Publish `connection_established`; do not assume the final ACK was visible |
| Initial attempt with no reply | Exists in Zeek, missing in Python | Publish `connection_attempt` semantic signal after Zeek's attempt delay |
| Setup rejected by responder RST | Exists in Zeek, missing in Python | Publish `connection_rejected` semantic signal |
| Established connection reset | Exists in Zeek, missing in Python | Publish `connection_reset` plus reset actor role |
| Exact SYN/SYN-ACK packet and retransmission count | Missing | Do not add now; would require the potentially expensive `connection_SYN_packet` hook |
| Full per-packet TCP flag counts | Missing and not justified | Do not implement |

This provides connection/SYN-attempt and outcome behavior at semantic-event
cost, while keeping the generic hot path free of packet callbacks.

## 12. Expiration and memory summary

| State | Primary window | Per-entry bounded structure | Whole-entry expiration |
|---|---|---|---|
| DDoS | short configurable buckets | bucket ring + capped source/port/protocol maps | no buckets and destination inactive |
| Scan | short/medium configurable buckets | bucket ring + capped IP/port/pair structures | no buckets and source inactive |
| Beacon | longer configurable horizon | time-and-count-capped deques | no samples/current episode and key inactive |
| DNS | source and domain horizons | bucket rings + capped domain/hash maps | source/domain windows empty and inactive |
| Exfil | medium/long configurable buckets | bucket ring + small protocol maps | no buckets and pair inactive |
| Encrypted | configurable buckets and session horizon | bucket ring + capped categories/sessions/deque | no buckets/sessions and key inactive |

No duration above is scientifically fixed. All horizons, bucket widths,
cleanup intervals, inactivity timeouts, and capacity limits belong in explicit
configuration.

## 13. Complexity summary

| State | Normal update time | Approximate memory driver |
|---|---:|---|
| DDoS | O(1) average | destinations × buckets × capped observed sources/ports |
| Scan | O(1) average | sources × buckets × capped destination fan-out |
| Beacon | amortized O(1) | keys × capped samples |
| DNS | O(query length), result O(1) | sources × capped domains × buckets/hashes |
| Exfil | O(1) average | directional IP pairs × buckets |
| Encrypted | O(1) average | service keys × buckets/categories/sessions + UID map |

Periodic whole-manager cleanup is O(number of active state entries), but it is
not performed for every event. Feature extraction may be linear in the bounded
buckets/samples for one requested key.

## 14. Exact key and required-data summary

| State system | Exact key |
|---|---|
| DDoSState | `dst_ip` |
| ScanState | `src_ip` |
| BeaconState | `(src_ip, dst_ip, dst_port, protocol)` |
| DNSState | `source_ip`, with bounded nested `registrable_domain` windows |
| ExfilState | `(src_ip, dst_ip)` directional pair |
| EncryptedState | `(client_ip, server_ip, server_port, ip_protocol, security_family)` |

Minimal data additions required before the relevant states are implemented:

| Addition | Existing Zeek source | Consumers |
|---|---|---|
| `DirectionalConnectionEvent` | Derived in the current cumulative adapter from validated snapshots | DDoS, Scan, Beacon |
| `TcpConnectionSignal` | `new_connection`, `connection_established`, `connection_attempt`, `connection_rejected`, `connection_reset` | DDoS, Scan |
| `DNSQueryObservation` | `dns_request` | DNS |
| `DNSResultObservation` | `DNS::log_dns` | DNS |
| `EncryptedProtocolObservation(identified)` | `ssl_client_hello`, first `QUIC::initial_packet` | Encrypted |
| `EncryptedProtocolObservation(metadata)` | `SSL::log_ssl`, `QUIC::log_quic` | Encrypted |

No new packet parser is required. Exact SYN-packet counts and JA3/JA4 client
fingerprints remain unavailable and are explicitly outside the first state
implementation. Standard Zeek logs continue unchanged.

## 15. Recommended implementation order

1. Add a common strict WebSocket event-envelope dispatcher while preserving
   the existing `iter_snapshots()` API.
2. Add the derived `DirectionalConnectionEvent` output to the cumulative
   adapter and test start/final/duplicate/flip/regression behavior.
3. Add the small Zeek/Python `TcpConnectionSignal` path using only high-level
   semantic events and the cheap `new_connection` SYN-start check.
4. Implement shared fixed bucket-ring, capped counter-map, capped hash-set, and
   cleanup primitives with deterministic event-time tests.
5. Implement `DDoSState` and `ScanState`; they validate the shared fan-out and
   TCP signal contracts.
6. Implement `ExfilState`; it is the simplest pure-delta volume state.
7. Implement `BeaconState`; it adds bounded ordered timing samples and episode
   grouping.
8. Add immediate DNS query/result transport, verify and pin offline
   `tldextract`/packaged-PSL compatibility, then implement `DNSState`.
9. Add TLS/DTLS/QUIC identification and metadata transport, then implement
   `EncryptedState` and its bounded UID join.
10. Run synthetic, PCAP, and live-interface state-update validation before
    beginning feature extraction or detectors.

Each step is a separate checkpoint. Do not add detector thresholds, malicious
labels, ML, alerting, storage, or dashboard behavior during state implementation.
