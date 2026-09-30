# External calibration datasets

Raw public and local PCAPs belong under `data/external/cache/`, which is
gitignored. The committed JSON manifests contain labels, endpoint metadata,
attack intervals, and immutable train/validation/test capture groups. Never put
different windows from one `split_group` into different roles.

Extraction uses the exact local events emitted by `zeek/flow_stream.zeek`, an
offline-only JSON sink, the production coordinator/state managers, and the
existing feature extractors. It does not infer runtime features from Zeek logs:

```bash
.venv/bin/python scripts/extract_external_dataset.py \
  datasets/manifests/local-hard-negatives.example.json
```

Trim large source captures to the documented labelled interval before replay,
but retain the original timestamp and endpoint metadata in the manifest. The
cache key includes the PCAP size/mtime, sampling interval, and runtime feature
schema hashes. Cached JSONL files are local artifacts, not committed evidence.

The templates cover CIC-DDoS2019, CIC-IDS2017, CTU-13, CIC-Bell-DNS-EXF-2021,
and local hard negatives. USTC-TFC2016 and CIRA-CIC-DoHBrw-2020 should only be
used for encrypted-state evaluation after confirming that each PCAP's client /
server identity, protocol family, and label scope map to the existing
`EncryptedTrafficFeatures`; CSV-only features are not compatible.
