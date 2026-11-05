# MELEF: Open Datasets for Cybersecurity Research (code release)

Code and data snapshot for the manuscript *An Evaluative Overview of Open Datasets for Cybersecurity Research: A Practical, Evidence-Based Approach* (Electronics, manuscript electronics-4565560).

**Cited release:** tag `v2.1`. The commit hash is given in the manuscript's Data Availability Statement.

## What reproduces what

| Manuscript element | Script | Output |
|---|---|---|
| Figure 1 (snapshot characteristics) | `make_figure1.py` | `results/dataset_characteristics_analysis.png` |
| Table 5, Section 4.3 (descriptive measures, overlap) | `snapshot_measures.py` | `results/snapshot_measures.json` |
| Section 4.4, Figure 2 (diagnostic pipeline) | `train_classifier.py` | `results/results.json`, `results/ml_performance_analysis.png`, `dataset.csv` |
| Section 4.2 protocol (Gate 1), for re-measurement | `accessibility_protocol.py` | `results/accessibility_log.jsonl` |
| Snapshot download (6 Aug 2025) | `download_real_datasets.py` | `real_data/` |
| Snapshot overview (`paper_results/analysis_results.json`) | `analyze_real_data.py` | `real_analysis_outputs/` |

```bash
pip install -r requirements.txt
python make_figure1.py
python snapshot_measures.py
python train_classifier.py
```

`run_complete_analysis.py` runs the full chain (download, overview, measures, pipeline, Figure 1) on freshly downloaded data in `real_data/`.

Both analysis scripts are deterministic (seed 42) and read the snapshot in `paper_results/`.

## Data snapshot

`paper_results/` holds the files analysed in the manuscript, retrieved on 6 August 2025 by `download_real_datasets.py`:

- `openphish_urls.txt`: OpenPhish community feed, 300 URLs.
- `urlhaus_data.csv`: URLhaus recent-URLs CSV dump, 19,540 records added between 7 July and 6 August 2025.
- `tranco_domains.csv`: Tranco top-1M list.
- `analysis_results.json`: overview statistics computed from the snapshot by `analyze_real_data.py`.

Each file remains subject to its provider's terms of use.

## Diagnostic pipeline (`train_classifier.py`)

The steps are:

- **Sampling.** 300 OpenPhish URLs plus 600 Tranco domains, drawn 200 from each rank tier (1–100K, 100K–500K, 500K–1M).
- **Cleaning.** Exact-duplicate removal, then conflict checks at FQDN and registered-domain level.
- **Features.** The 15 features of Table 6, computed on each record as supplied by its source.
- **Partitioning.** Records are grouped by registered domain (Public Suffix List). A stratified group split holds out about 20%. 10-fold `StratifiedGroupKFold` CV runs on the training partition.
- **Models.** Random Forest (`n_estimators=100, max_depth=15, min_samples_split=5`) and a Logistic Regression baseline.
- **Representation-matched check.** The same protocol with every record reduced to its registered domain.

The sample and partition assignment are written to `dataset.csv`.

## Accessibility protocol (`accessibility_protocol.py`)

This script implements the protocol of Section 4.2:

- five attempts per dataset at 12-hour intervals;
- 30 s timeout;
- descriptive User-Agent;
- back-off on HTTP 429/5xx;
- a per-request JSON-lines log.

It is a re-implementation released in November 2026 so that the measurement can be repeated against current endpoints. The May 2025 measurements reported in the manuscript were taken with the authors' original test harness.

## History

The earlier exploratory implementation (`real_phishing_detector.py`, TF-IDF character n-grams, sample-level split) was removed in commit `50b6311`. Its outputs (`url_vectorizer.pkl`, `phishing_classifier.pkl`, `model_metadata.json`, `model_performance.png`) were removed in `v2.1`, together with an earlier summary figure (`complete_analysis_summary.png`) whose "suitability scores" were fixed values in the code rather than computed from data. Its results are not reported in the manuscript.
