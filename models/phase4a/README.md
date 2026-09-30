# Phase 4A Model Artifacts

Regenerate all artifacts, manifests, datasets, and validation metrics offline with:

```bash
.venv/bin/python scripts/train_models.py
```

The four flow-family artifacts are binary `RandomForestClassifier` models over the existing runtime feature extractors. The DGA artifact is a character 3–5 gram TF-IDF plus logistic-regression pipeline over normalized DNS query strings.

Every artifact has an exact JSON schema manifest. Runtime loading disables an absent or schema-incompatible model instead of inventing inputs. Joblib artifacts must only be loaded from this trusted project directory.

All included metrics are deterministic synthetic/lab validation metrics and are not claims of production or real-world accuracy.
