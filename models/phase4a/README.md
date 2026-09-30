# Phase 4A Model Artifacts

Regenerate the four synthetic behavioral artifacts with:

```bash
.venv/bin/python scripts/train_models.py
```

Then restore/retrain the committed public-research-corpus DGA artifact with:

```bash
.venv/bin/python scripts/train_research_dga.py \
  --corpus data/external/cache/dga_domains_full.csv
```

The four flow-family artifacts remain synthetic-data `RandomForestClassifier`
models over the existing runtime feature extractors. The DGA artifact is a
character 3–5 gram TF-IDF plus class-weighted logistic-regression pipeline with
sigmoid calibration, trained on the public DGA_domains_dataset with malware
families held out across partitions.

Every artifact has an exact JSON schema manifest. Runtime loading disables an absent or schema-incompatible model instead of inventing inputs. Joblib artifacts must only be loaded from this trusted project directory.

Behavioral metrics remain deterministic synthetic/lab validation metrics. DGA
metrics are public research-corpus lab generalization results and still are not
claims of live-network or production accuracy. See `CALIBRATION_REPORT.md`.
