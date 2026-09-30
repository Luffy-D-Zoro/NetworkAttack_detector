# Real-Data Calibration Report

## Scope and data status

This checkpoint adds a reusable real-PCAP calibration path and hardens two
false-positive semantics without changing the streaming architecture. Raw
datasets remain outside Git under `data/external/cache/`.

Actually processed during this checkpoint:

- **DGA_domains_dataset**: 674,898 public research rows, 25 malware DGA
  families plus Alexa-labelled legitimate domains. Source SHA-256:
  `e8bbe54f180cd127a07abaa3dbddcd843e7b7943dff2f18628619b1bd22e8253`.
- **Zeek packaged conn-size fixture**: replayed only to validate the offline
  Zeek → exact production events → coordinator/state → production feature
  extractor harness. Its rows were not used as field-labelled model evidence.

Not downloaded or processed here: CIC-DDoS2019, CIC-IDS2017, CTU-13,
CIC-Bell-DNS-EXF-2021, USTC-TFC2016, CIRA-CIC-DoHBrw-2020, and owner-local
benign captures. Their raw PCAPs were absent from the workspace; several are
large or require an interactive/licensed download. No behavioral model or
fusion setting was tuned by pretending that missing data existed.

## Leakage-safe extraction

`scripts/extract_external_dataset.py` loads strict manifests, runs each PCAP
through Zeek's production `flow_stream.zeek` event producers, sends those exact
event objects through the existing coordinator/state managers, and periodically
calls the existing feature extractors. It never imports CICFlowMeter columns.

The offline-only `calibration_capture.zeek` sink is enabled with
`FlowStream::emit_local_events=T` and `FlowStream::enable_websocket=F`; live
defaults remain unchanged. Cached JSONL rows include capture, dataset,
`split_group`, explicit train/validation/test role, subject, exact runtime
schema values, and the contemporaneous rule result. Cache keys include PCAP
identity, sampling interval, and runtime schema hashes.

Manifest validation rejects any `split_group` that appears in more than one
role. Attack windows and known attacker/victim/source/destination metadata can
limit positive rows. Unreliable background data cannot be silently labelled
benign.

## Semantic corrections

- Beacon destinations are classified with Python standard IP semantics.
  IPv4/IPv6 multicast, limited broadcast, and unspecified destinations remain
  monitored and retained in state, but their periodicity is not unicast C2
  evidence. Private unicast remains eligible. Directed subnet broadcast cannot
  be identified without interface-prefix context and remains a limitation.
- Scan fan-out now uses TCP outcomes as counterevidence. High horizontal
  fan-out with at least 80% establishment and at most 10% rejection/no-reply is
  treated as successful service/CDN behavior, not a scan solely due to fan-out.
  Horizontal/vertical scans with failures or unavailable reverse outcomes
  remain eligible.
- Existing DDoS logic already requires a distributed, high-entropy observed-
  source profile rather than volume alone. Exfiltration requires both volume
  and sustained activity. DNS tunneling/DGA behavior and encrypted traffic
  rules already require multiple indicators. Regression tests preserve these
  constraints.

## DGA retraining and held-out results

The algorithm remains character 3–5 gram TF-IDF plus class-weighted logistic
regression. A sigmoid calibrator was fitted on a separate half of validation
data. DGA malware families—not rows—were assigned to train, validation, or
untouched test, so test families were unseen during fitting and threshold
selection. Legitimate domains were deterministically assigned by domain hash.

| Partition | Samples | Purpose |
|---|---:|---|
| Train | 60,000 | base TF-IDF/logistic model |
| Calibration | 9,983 | sigmoid score calibration |
| Validation tuning | 10,017 | alert threshold selection |
| Untouched test | 20,000 | one final held-out evaluation |

The validation-selected DGA alert threshold is `0.891`, selected under a 1%
validation false-positive-rate constraint.

| Split | TP | FP | TN | FN | Precision | Recall | F1 | FPR | PR-AUC | ROC-AUC |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Validation tuning | 2,576 | 49 | 4,905 | 2,487 | 0.9813 | 0.5088 | 0.6701 | 0.00989 | 0.9279 | 0.9112 |
| Held-out families test | 4,755 | 129 | 9,871 | 5,245 | 0.9736 | 0.4755 | 0.6389 | 0.01290 | 0.9392 | 0.9409 |

These are public research-corpus lab generalization results, not live-network
accuracy. The conservative threshold substantially favors precision over
recall. Exact family assignments and metrics are stored in
`models/phase4a/dga.manifest.json` and `dga.realdata.metrics.json`.

## Behavioral candidate comparison and fusion

`scripts/calibrate_behavioral_models.py` compares class-weighted logistic
regression, random forest, and histogram gradient boosting using explicit
capture-group train/validation/test roles. Selection uses validation PR-AUC,
F1, and FPR; the final test is evaluated only after selection. It also performs
a transparent per-family rule/ML weight and alert-threshold grid search on
validation rows. Runtime fusion now supports immutable per-family overrides.

No DDoS, scan, exfiltration, or beacon model was replaced and their equal-weight
fusion defaults were not relabelled “calibrated,” because compatible labelled
PCAP rows and local hard-negative captures were not available in this run.

## Encrypted-dataset compatibility

USTC-TFC2016 and CIRA-CIC-DoHBrw-2020 can only be used when raw PCAP capture
labels can be mapped to client/server/session subjects produced by the existing
TLS/DTLS/QUIC state. Their supplied external CSV feature columns are not runtime
compatible. No encrypted model was trained. CIRA-CIC-DoHBrw-2020 is a plausible
evaluation source because raw PCAPs are documented, but capture/interval label
scope must be checked before assigning positives. USTC application/malware
labels must not be equated automatically with a specific encrypted session.

## Remaining measurements

Alerts/hour and false alerts by family on idle, browser, video/CDN, GitHub,
download, package-update, QUIC, DNS, discovery, long-lived, periodic-service,
and cloud-upload captures remain unmeasured until those owner-confirmed benign
PCAPs are supplied. The committed local hard-negative manifest makes those
sessions capture-group isolated when they become available.
