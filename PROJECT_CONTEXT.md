# PROJECT_CONTEXT.md

# Project: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

This file is the **authoritative architecture and implementation context** for this project.

Whenever working on this repository:

1. Read this file before making architectural decisions.
2. Read `HANDOFF.md` to understand what has already been implemented.
3. Do not redesign the architecture unless explicitly instructed by the project owner.
4. Implement only the requested checkpoint.
5. After making meaningful changes, update `HANDOFF.md`.

---

# 1. Project Goal

We are building a prototype for passive detection of cyber threats from **unidirectional network traffic**.

The system observes a one-way copy of traffic from a gateway/network link and detects suspicious behavior while traffic is still running.

This is a **network monitoring system**, not an endpoint antivirus.

It can observe traffic involving many:

- source IPs
- destination IPs
- hosts
- ports
- protocols
- network flows

The system should detect threats through behavioral, statistical, protocol-metadata, ML, and anomaly-based analysis.

---

# 2. Fundamental Constraints

The monitoring system is completely passive.

It may:

```text
capture
observe
parse
aggregate
calculate
detect
score
alert
```

It must NOT:

```text
send probes
inject packets
reply to traffic
block traffic
modify firewall rules
terminate connections
actively scan machines
change monitored network state
```

The monitored traffic should be treated as **read-only input**.

---

# 3. Unidirectional Traffic

The system must work even when only one direction of communication is visible.

Therefore:

- detectors must not require complete bidirectional conversations;
- unavailable reverse-direction information must not break processing;
- bidirectional information may be used if available, but it must not be assumed.

Do not silently design features that require both directions.

---

# 4. Encryption

TLS/QUIC traffic must NOT be decrypted.

Detection may use observable metadata such as:

```text
source/destination IP
source/destination port
protocol
packet size
timing
frequency
connection duration
TLS metadata
QUIC metadata
fingerprints where available
connection patterns
```

The system is primarily metadata/behavior based.

---

# 5. Core Streaming Architecture

The agreed architecture is:

```text
                    NETWORK TRAFFIC
                           │
                           ▼
                    PACKET CAPTURE
                           │
                     continuous stream
                           │
                           ▼
                          ZEEK
                           │
                 metadata/log events
                    as traffic arrives
                           │
                           ▼
                    FLOW MANAGER
                           │
                     FlowState
                           │
                           ▼
                ATTACK-SPECIFIC STATES
                           │
                 detector-specific
                  recent time windows
                           │
                           ▼
                       FEATURES
                           │
             ┌─────────────┼─────────────┐
             ▼             ▼             ▼
           RULES      PRETRAINED ML    ANOMALY
             │             │             │
             └─────────────┼─────────────┘
                           ▼
                     SCORE / FUSION
                           │
                           ▼
                     STRUCTURED ALERT
                           │
                  ┌────────┴────────┐
                  ▼                 ▼
             ALERT STORAGE      DASHBOARD
```

This is the project architecture unless explicitly changed.

---

# 6. Role of Zeek

Zeek is the primary protocol-aware metadata extraction layer.

Instead of manually implementing every network protocol parser in Python, Zeek observes live traffic and produces structured metadata/log events continuously.

Relevant Zeek outputs may include information equivalent to:

```text
connection metadata
DNS metadata
TLS metadata
HTTP metadata where visible
protocol/service information
timestamps
byte/packet statistics
connection state information
```

Common Zeek logs may later include:

```text
conn.log
dns.log
ssl.log / tls-related logs depending on Zeek version/configuration
http.log
```

Do not assume that every Zeek log is required.

Use only the information actually needed by our detectors.

---

# 7. Zeek Is Streaming, Not Batch Processing

Do NOT design the system as:

```text
capture traffic for 30 minutes
        ↓
wait
        ↓
read completed Zeek logs
        ↓
analyze everything
```

The desired behavior is:

```text
traffic arrives
      ↓
Zeek processes traffic
      ↓
metadata/log event becomes available
      ↓
Python processing consumes it
      ↓
states are updated
      ↓
detection continues while traffic is running
```

If an attack occurs at minute 5 of a 30-minute observation period, the system should potentially detect it around minute 5.

---

# 8. Raw Packet Retention

Raw packets should normally not be retained after required processing.

The system should primarily store derived metadata and state.

PCAP may be used only for:

```text
testing
debugging
replay
benchmarking
demonstration
```

PCAP is NOT the normal runtime storage model.

---

# 9. Flow Manager

Python receives useful metadata produced from the traffic stream and maintains active flow state.

The logical flow key is initially:

```text
(
    src_ip,
    src_port,
    dst_ip,
    dst_port,
    protocol
)
```

This is directional.

Example:

```text
10.0.0.5:50000 → 8.8.8.8:53 UDP
```

and

```text
8.8.8.8:53 → 10.0.0.5:50000 UDP
```

must not automatically become the same flow.

Do not canonicalize or merge directions unless explicitly requested later.

---

# 10. FlowState

`FlowState` represents ONE communication flow.

It stores compact derived state, not packet objects.

Conceptually:

```text
FlowState {
    src_ip
    src_port
    dst_ip
    dst_port
    protocol

    first_seen
    last_seen

    packet_count
    byte_count

    tcp-related counters where available

    other compact statistics required later
}
```

If a flow contains 10,000 packets, we should store something like:

```text
packet_count = 10000
```

not 10,000 packet objects.

---

# 11. Memory Must Remain Bounded

The program must be able to operate continuously.

Memory must therefore remain bounded using:

```text
inactive flow expiration
rolling time windows
expired bucket deletion
bounded histories
state cleanup
```

Never build structures that grow forever.

---

# 12. Flow Expiration

Every active flow should contain enough timing information to determine inactivity.

At minimum:

```text
first_seen
last_seen
```

Inactive flows should eventually be removed.

Timeouts are experimental values.

Keep them configurable.

Do not treat one arbitrary timeout as scientifically final.

Cleanup also does not need to run for every event if periodic cleanup is more efficient.

---

# 13. Attack-Specific State

After basic flow management works, separate detector states will be implemented.

These are NOT copies of FlowState.

Each should contain only the information required for its detector.

Planned states:

```text
DDoSState
BeaconState
DNSState
ScanState
ExfilState
EncryptedState
```

Do not implement these until explicitly requested.

---

# 14. DDoSState

Likely organized primarily around:

```text
destination_ip
```

Possible information:

```text
recent packet rate
recent byte rate
SYN count
UDP count
observed source-IP frequencies
unique observed source IPs
source-IP entropy
protocol distribution
recent time buckets
```

Important:

Do not assume a destination is already known to be a victim.

The system discovers destinations exhibiting DDoS-like behavior.

Also use the phrase:

```text
observed source IP
```

rather than claiming:

```text
true attacker IP
```

because source addresses may be spoofed.

---

# 15. BeaconState

Possible logical key:

```text
(src_ip, dst_ip, dst_port, protocol)
```

Possible information:

```text
contact timestamps
inter-arrival times
mean interval
variance / jitter
connection frequency
duration statistics
size statistics
periodicity
```

Beaconing generally needs longer historical context than short DDoS detection windows.

---

# 16. DNSState

Possible organization:

```text
source
domain
source + domain
```

Possible information:

```text
query count
query frequency
query length
domain length
subdomain length
character entropy
unique domains
unique subdomains
repetition patterns
```

This may later support:

```text
DNS tunneling
DGA detection
abnormal DNS behavior
```

Zeek DNS metadata will be especially useful here.

---

# 17. ScanState

Likely keyed by:

```text
source_ip
```

Possible information:

```text
unique destination IPs
unique destination ports
connection attempts
SYN attempts
fan-out
recent destination activity
```

---

# 18. ExfilState

Likely organized around:

```text
(src_ip, dst_ip)
```

Possible information:

```text
bytes
packets
duration
transfer rate
persistent transfer behavior
directional ratios where meaningful
```

The detector must remain useful even when complete bidirectional traffic is unavailable.

---

# 19. EncryptedState

Possible information:

```text
TLS metadata
QUIC metadata
fingerprints when available
packet/flow sizes
timing
duration
frequency
connection patterns
```

No payload decryption.

Zeek protocol metadata can be used where available.

---

# 20. Rolling Windows

A rolling window is NOT another global storage layer.

It defines how much recent history a detector needs.

Example:

```text
DDoS detector
    → short recent window

Scan detector
    → short/medium recent window

Beacon detector
    → much longer history
```

Different detectors can use different windows.

Do NOT force all detectors to use one common window.

Possible implementation:

```text
time bucket 1
time bucket 2
time bucket 3
...
```

Expired buckets should be deleted.

Window durations should remain configurable and be tuned experimentally.

---

# 21. Detection Strategy

The planned detection system is hybrid:

```text
STATISTICAL / BEHAVIORAL RULES
              +
       PRETRAINED ML
              +
      ANOMALY DETECTION
              ↓
        SCORE / FUSION
              ↓
             ALERT
```

Different threat types may use different approaches.

Do not attempt to force every attack through one ML model.

---

# 22. Candidate ML Approaches

Current candidates include:

```text
CICIDS2017-trained LightGBM/classifier
Isolation Forest
pretrained DGA CNN
```

These are candidates, not guaranteed final choices.

Before integrating any pretrained model, verify compatibility between its expected features and our features.

Check:

```text
feature names
feature definitions
units
ordering
normalization
aggregation interval
directionality
missing values
training preprocessing
```

Never blindly feed our FlowState fields into a pretrained model.

---

# 23. Detection Philosophy

Do not make simplistic conclusions such as:

```text
high traffic == DDoS
many destinations == scan
large transfer == exfiltration
periodic traffic == malware beacon
encrypted traffic == malicious
```

Each signal is evidence.

Later detectors should combine multiple indicators when appropriate.

---

# 24. Prototype Technology Stack

The prototype is being built using:

```text
Zeek
Python
Python state-management / detection code
classical ML / anomaly detection
Streamlit dashboard
```

Do not introduce another implementation language or completely different technology stack unless explicitly instructed.

---

# 25. Suggested Python Project Structure

The exact structure may evolve, but responsibilities should remain separated.

Example:

```text
project/
│
├── PROJECT_CONTEXT.md
├── HANDOFF.md
├── README.md
├── requirements.txt
│
├── src/
│   ├── ingestion/
│   │   ├── zeek_reader.py
│   │   └── ...
│   │
│   ├── flow/
│   │   ├── models.py
│   │   ├── flow_manager.py
│   │   └── ...
│   │
│   ├── states/
│   ├── detectors/
│   ├── ml/
│   ├── alerts/
│   └── main.py
│
└── tests/
```

Do not create all future directories/files unnecessarily during the first milestone.

The structure above exists only to show separation of responsibilities.

Avoid both:

```text
one huge Python file
```

and unnecessary enterprise-style over-engineering.

---

# 26. Immediate Implementation Milestone

THIS IS THE CURRENT DEVELOPMENT TARGET.

Do not implement later detection stages yet.

We currently want to reach:

```text
LIVE NETWORK INTERFACE
        ↓
ZEEK PROCESSING
        ↓
STREAMING ZEEK METADATA
        ↓
Python ingestion
        ↓
extract/use required metadata:

timestamp
source IP
destination IP
source port
destination port
protocol
packet/byte information
TCP/connection information where available

        ↓
construct FlowKey

(src_ip,
 src_port,
 dst_ip,
 dst_port,
 protocol)

        ↓
HASH-TABLE LOOKUP
        ↓

existing flow?
    YES → update FlowState
    NO  → create FlowState

        ↓
expire inactive FlowStates

        ↓
print / inspect active flows
```

Do not implement ML, attack detection, dashboard, score fusion, or alert storage yet.

---

# 27. Current Processing Concept

Conceptually:

```text
Zeek event/log entry arrives
        ↓
parse required fields
        ↓
convert to internal metadata representation
        ↓
construct FlowKey
        ↓
flow_manager.update(...)
        ↓
discard temporary event object if no longer needed
        ↓
periodically expire inactive flows
        ↓
periodically inspect active flows
```

The exact API may differ.

Preserve the architecture.

---

# 28. Performance Principles

Even though this is a prototype, avoid obviously inefficient designs.

Use:

```text
FlowKey → FlowState
```

through a Python hash table / dictionary.

Do not scan every active flow for every incoming event.

Avoid:

```text
unbounded lists
unnecessary object copying
repeated parsing
excessive logging in hot paths
storing full raw events forever
```

Detector execution later should not automatically run for every individual packet/event.

---

# 29. Concurrency

Do not introduce:

```text
asyncio
multiprocessing
thread pools
complex queues
shared memory
locks
```

unless they are actually necessary.

A simple streaming loop is preferred initially.

Optimize only after measuring an actual bottleneck.

---

# 30. Configuration

Values expected to change during experimentation must remain configurable.

Examples:

```text
network interface
Zeek log/event source
flow inactivity timeout
cleanup interval
inspection interval
future detector windows
future thresholds
```

Avoid scattered magic constants.

---

# 31. Testing

The core processing logic should remain testable independently from live network capture.

Where possible, we should eventually be able to provide:

```text
live Zeek events
saved Zeek logs
synthetic metadata
test objects
PCAP replay through Zeek
```

to the processing pipeline.

Live streaming remains the primary runtime mode.

---

# 32. Error Handling

Unexpected network events must not terminate the monitoring system.

Handle cases such as:

```text
missing fields
unsupported protocols
malformed entries
incomplete connections
non-TCP/UDP traffic
unexpected Zeek values
```

gracefully.

However, do not hide programming errors using broad `except Exception: pass` logic.

---

# 33. Mandatory Architecture Rules

Do NOT violate these rules:

```text
1. Do not turn the project into an endpoint antivirus.

2. Do not send traffic into the monitored network.

3. Do not actively probe machines.

4. Do not require TLS/QUIC decryption.

5. Do not use batch-only processing.

6. Do not wait until the entire capture finishes before detection.

7. Do not store every raw packet.

8. Do not allow state to grow forever.

9. Do not assume source IP == true attacker.

10. Do not assume destination == confirmed victim.

11. Do not require bidirectional traffic.

12. Do not use one global time window for every detector.

13. Do not run ML for every packet/event by default.

14. Do not blindly feed incompatible features into pretrained ML models.

15. Do not replace the directional FlowKey without explicit instruction.

16. Do not bypass the agreed Zeek → Python Flow Manager architecture.

17. Do not implement future stages early.

18. Do not over-engineer the prototype.

19. Do not silently make major architecture decisions.

20. Do not introduce another technology stack unless explicitly requested.
```

---

# 34. Development Order

The intended order is:

```text
PHASE 1 — CURRENT

live traffic
    ↓
Zeek
    ↓
streaming metadata ingestion
    ↓
FlowKey
    ↓
FlowState
    ↓
Flow Manager
    ↓
flow expiration
    ↓
active-flow inspection
```

After Phase 1 works:

```text
PHASE 2

DDoSState
BeaconState
DNSState
ScanState
ExfilState
EncryptedState
```

Then:

```text
PHASE 3

rolling windows
feature extraction
behavioral/statistical detectors
```

Then:

```text
PHASE 4

pretrained-model compatibility analysis
ML integration
Isolation Forest / anomaly detection
DGA model integration
```

Then:

```text
PHASE 5

score fusion
structured alerts
alert storage
Streamlit dashboard
```

Do not skip phases without explicit instruction.

---

# 35. Working Style for Codex

For each task:

1. Read `PROJECT_CONTEXT.md`.
2. Read `HANDOFF.md`.
3. Inspect the relevant existing files.
4. Implement only the requested change.
5. Do not independently start the next phase.
6. Run appropriate checks/tests.
7. Update `HANDOFF.md`.

When choosing between implementations, prefer:

```text
simple
explicit
testable
efficient enough
easy to understand
compatible with future phases
```

Do not redesign working components merely for style.

---

# 36. HANDOFF.md — Mandatory Project Memory

`HANDOFF.md` is the project's running implementation record.

It exists so that future Codex sessions can immediately understand:

```text
what currently exists
what has already been implemented
what decisions were made
what files were changed
what currently works
what is incomplete
what bugs/issues remain
what should happen next
```

Before beginning new work:

```text
READ PROJECT_CONTEXT.md
READ HANDOFF.md
```

After making any meaningful project change:

```text
UPDATE HANDOFF.md
```

This is mandatory.

---

# 37. HANDOFF.md Format

Maintain `HANDOFF.md` approximately like this:

```markdown
# Project Handoff

## Current Phase

Phase 1 — Zeek streaming metadata → Flow Manager

## Current Status

Short description of what currently works.

## Architecture Decisions Made

- decision
- decision
- decision

## Implemented Components

### component/file

What it does.

### component/file

What it does.

## Files Added

- path
- path

## Files Modified

- path
- path

## How To Run

Commands required to run the current prototype.

## How To Test

Commands/tests and expected behavior.

## Known Issues / Limitations

- issue
- limitation

## Current Configuration

Relevant runtime/configuration assumptions.

## Next Intended Step

Exactly what should be implemented next.

## Last Change

Short description of the most recent work.
```

---

# 38. HANDOFF Rules

When updating `HANDOFF.md`:

Do NOT rewrite history incorrectly.

Do NOT say something works unless it was actually implemented/tested.

Clearly distinguish:

```text
implemented
tested
planned
partially implemented
known broken
```

Keep it concise enough that another Codex session can quickly understand the project.

Do not turn it into a huge development diary.

It should represent the **current state of the repository**.

---

# 39. If PROJECT_CONTEXT.md and HANDOFF.md Conflict

`PROJECT_CONTEXT.md` defines the intended architecture.

`HANDOFF.md` describes the current implementation state.

Therefore:

```text
PROJECT_CONTEXT.md
        =
architecture / design source of truth

HANDOFF.md
        =
implementation/progress source of truth
```

If implementation in `HANDOFF.md` appears to contradict `PROJECT_CONTEXT.md`, do not silently continue the contradiction.

Report the discrepancy before making architectural changes.

---

# 40. Current Boundary

The project is currently in:

```text
PHASE 1
```

Until explicitly instructed otherwise, do NOT implement:

```text
DDoS detection
scan detection
beacon detection
DNS tunneling detection
DGA detection
exfiltration detection
encrypted-traffic detection
LightGBM
Isolation Forest
CNN inference
score fusion
alert storage
Streamlit dashboard
```

The current objective is only:

```text
live traffic
    ↓
Zeek
    ↓
streaming metadata
    ↓
Python
    ↓
FlowKey
    ↓
FlowState
    ↓
Flow Manager
    ↓
expiration
    ↓
inspection
```

---

# 41. Final Principle

The system should continuously transform traffic into **small, useful, bounded state**.

Conceptually:

```text
traffic
  ↓
Zeek metadata
  ↓
compact flow state
  ↓
compact detector-specific state
  ↓
features
  ↓
detection
  ↓
alerts
```

Never allow the implementation to drift into:

```text
capture everything
store everything
analyze everything later
```

This is a streaming behavioral threat-detection system.

Follow this file unless explicitly instructed otherwise.