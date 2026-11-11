# MELEF: Open Datasets for Cybersecurity Research (code release)

Code and data snapshot for the manuscript *An Evaluative Overview of Open Datasets for Cybersecurity Research: A Practical, Evidence-Based Approach* (Electronics, manuscript electronics-4565560).

**Cited release:** tag `v2.2` (supersedes `v2.1`). The commit hash is given in the manuscript's Data Availability Statement.

## What reproduces what

| Manuscript element | Script | Output |
|---|---|---|
| Figure 1 (snapshot characteristics) | `make_figure1.py` | `results/dataset_characteristics_analysis.pdf` / `.png` (600 dpi) |
| Table 5, Section 4.3 (descriptive measures, overlap) | `snapshot_measures.py` | `results/snapshot_measures.json` |
| Section 4.4, Figure 2 (diagnostic pipeline) | `train_classifier.py` | `results/results.json`, `results/ml_performance_analysis.pdf` / `.png` (600 dpi), `dataset.csv` |
| Section 4.4.4, Table 7, Figure 3 (Common Crawl benign URLs, temporal test) | `extended_evaluation.py` | `results/extended_results.json`, `results/extended_evaluation.pdf` / `.png`, collected files listed below |
| Section 4.2 protocol (Gate 1), for re-measurement | `accessibility_protocol.py` | `results/accessibility_log.jsonl` |
| Snapshot download (6 Aug 2025) | `download_real_datasets.py` | `real_data/` |
| Snapshot overview (`paper_results/analysis_results.json`) | `analyze_real_data.py` | `real_analysis_outputs/` |

```bash
pip install -r requirements.txt
python make_figure1.py
python snapshot_measures.py
python train_classifier.py
python extended_evaluation.py evaluate   # offline, from the released collected files
```

`run_complete_analysis.py` runs the full chain (download, overview, measures, pipeline, Figure 1) on freshly downloaded data in `real_data/`.

The analysis scripts are deterministic (seed 42; seed 43 for the Experiment B benign sample) and read the snapshot in `paper_results/` and the collected files in `results/`.

## Data snapshot

`paper_results/` holds the files analysed in the manuscript, retrieved on 6 August 2025 by `download_real_datasets.py`:

- `openphish_urls.txt`: OpenPhish community feed, 300 URLs.
- `urlhaus_data.csv`: URLhaus recent-URLs CSV dump, 19,540 records added between 7 July and 6 August 2025.
- `tranco_domains.csv`: Tranco top-1M list.
- `analysis_results.json`: overview statistics computed from the snapshot by `analyze_real_data.py`.

Each file remains subject to its provider's terms of use.

When the feeds were retrieved again on 11 November 2026, the URLhaus `downloads/csv_recent/` endpoint used for this snapshot returned HTTP 410 (Gone), and the OpenPhish feed URL redirected to `raw.githubusercontent.com/openphish/public_feed`.

## Diagnostic pipeline (`train_classifier.py`)

The steps are:

- **Sampling.** 300 OpenPhish URLs plus 600 Tranco domains, drawn 200 from each rank tier (1–100K, 100K–500K, 500K–1M).
- **Cleaning.** Exact-duplicate removal, then conflict checks at FQDN and registered-domain level.
- **Features.** The 15 features of Table 6, computed on each record as supplied by its source.
- **Partitioning.** Records are grouped by registered domain (Public Suffix List). A stratified group split holds out about 20%. 10-fold `StratifiedGroupKFold` CV runs on the training partition.
- **Models.** Random Forest (`n_estimators=100, max_depth=15, min_samples_split=5`) and a Logistic Regression baseline.
- **Representation-matched check.** The same protocol with every record reduced to its registered domain.

The sample and partition assignment are written to `dataset.csv`.

## Extended evaluation (`extended_evaluation.py`, Round 4)

Replaces the 600 bare Tranco domains with 600 benign **full URLs** collected independently from Common Crawl, keeping the phishing records, the 15 features, the models and registered-domain grouping unchanged, and adds a temporally separated test set.

- **Benign URLs.** For each sampled Tranco domain, one capture with HTTP 200, `text/html` and a non-root path is drawn at random from the Common Crawl ZipNum CDX index (`cluster.idx` plus HTTP range requests on `data.commoncrawl.org`). Domains without such a capture are replaced by random domains of the same rank tier until 200 URLs per tier; threat-feed registered domains are excluded.
- **Experiment A (same period).** 300 OpenPhish URLs (6 Aug 2025) + 600 URLs from `CC-MAIN-2025-33` (2–15 Aug 2025). Grouped, stratified 5-fold CV over all records; ROC-AUC, balanced accuracy, accuracy, per-class recall.
- **Experiment B (temporal).** Train on all of A; test on the OpenPhish feed of 11 Nov 2026 and 600 URLs from `CC-MAIN-2026-43` (5–18 Oct 2026) for domains sampled from the Tranco list of 11 Nov 2026. Test records sharing a registered domain with training are removed (72 phishing URLs, mostly hosting platforms).
- **Sensitivity.** S1: root-path phishing URLs removed; S2: leading `www.` stripped; S3: both.

Collected files (in `results/`): `benign_cc_train.csv`, `benign_cc_test.csv`, `openphish_test.txt`, `tranco_test_top1m.csv.zip`, `collection_log.json`. `python extended_evaluation.py collect` repeats the collection (network access to `data.commoncrawl.org`, `openphish.com`, `tranco-list.eu`); a new collection will differ because the feeds change. The index caches `results/cluster_*.idx` (about 100 MB each) are not tracked.

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
