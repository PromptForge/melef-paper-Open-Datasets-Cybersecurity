"""
Diagnostic classification pipeline (Gate 3) for manuscript electronics-4565560:
"An Evaluative Overview of Open Datasets for Cybersecurity Research".

Every value reported in Section 4.4 and Figure 2 of the manuscript is produced
by this script, run on the snapshot files in paper_results/:

    python train_classifier.py            # writes results/ and dataset.csv

Steps
  1. Load the 300 OpenPhish URLs and the Tranco list (snapshot of 6 Aug 2025).
  2. Draw 600 benign domains by stratified random sampling: 200 from each of the
     rank tiers 1-100K, 100,001-500K, 500,001-1M (seed 42).
  3. Remove exact duplicate records, then check label conflicts between the
     benign sample and both threat feeds at FQDN and registered-domain level.
  4. Extract the 15 features of Table 6 from each record *as supplied by its
     source* (OpenPhish: full URL; Tranco: bare domain, no scheme or path).
  5. Group records by registered domain (Public Suffix List, offline snapshot
     bundled with tldextract) and hold out ~20% with a stratified group split.
  6. 10-fold StratifiedGroupKFold cross-validation on the training partition,
     then a single evaluation on the held-out partition.
  7. Random Forest (n_estimators=100, max_depth=15, min_samples_split=5) and a
     Logistic Regression baseline (standardized features) on identical splits.
  8. Representation-matched check: every record reduced to its registered
     domain, domain-level features only, same protocol.
  9. Gini importances, the 7 ad hoc examples of the original release, and
     Figure 2 (results/ml_performance_analysis.png).
"""
import csv
import json
import os
import random
import urllib.parse

import numpy as np
import tldextract
from scipy import stats
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, confusion_matrix,
                             precision_recall_fscore_support)
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

SEED = 42
N_ESTIMATORS, MAX_DEPTH, MIN_SAMPLES_SPLIT = 100, 15, 5
TIERS = [(0, 100_000), (100_000, 500_000), (500_000, 1_000_000)]
PER_TIER = 200
DATA_DIR = os.environ.get("MELEF_DATA", "paper_results")
OUT_DIR = "results"

FEATURES = ["url_len", "special_.", "special_-", "special_/", "special_=",
            "special_?", "special_&", "special_@", "has_login",
            "hostname_len", "subdomain_count", "tld_len",
            "path_len", "path_levels", "has_exe"]
DOMAIN_FEATURES = ["hostname_len", "special_.", "special_-", "tld_len", "has_login"]

# Offline Public Suffix List snapshot (no network access needed).
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())

# The seven ad hoc examples used in the original release (real_phishing_detector.py).
ADHOC = ["https://google.com", "https://github.com",
         "http://suspicious-bank-login.tk/verify.php", "https://facebook.com",
         "http://paypal-security-update.ml/login", "https://amazon.com",
         "https://microsoft.com"]


def parse(record):
    """Hostname and path of a record; a scheme is added only for parsing."""
    s = record if record.startswith(("http://", "https://")) else "http://" + record
    p = urllib.parse.urlparse(s)
    return p.netloc.split(":")[0].lower(), p.path


def registered_domain(host):
    e = _EXTRACT(host)
    rd = e.top_domain_under_public_suffix if hasattr(e, "top_domain_under_public_suffix") else e.registered_domain
    return rd or host


def extract_15_features(record):
    """The 15 features of Table 6, computed on the record string as supplied."""
    host, path = parse(record)
    labels = host.split(".")
    return [
        len(record),                         # url_len
        record.count("."),                   # special_.
        record.count("-"),                   # special_-
        record.count("/"),                   # special_/
        record.count("="),                   # special_=
        record.count("?"),                   # special_?
        record.count("&"),                   # special_&
        record.count("@"),                   # special_@
        int("login" in record.lower()),      # has_login
        len(host),                           # hostname_len
        max(0, len(labels) - 2),             # subdomain_count: labels beyond the last two
        len(labels[-1]) if len(labels) > 1 else 0,   # tld_len: last label
        len(path),                           # path_len
        len([seg for seg in path.split("/") if seg]),  # path_levels
        int(".exe" in path.lower()),         # has_exe
    ]


def domain_features(record):
    """Domain-level features on the registered domain (representation-matched check)."""
    rd = registered_domain(parse(record)[0])
    return [len(rd), rd.count("."), rd.count("-"),
            len(rd.rsplit(".", 1)[-1]) if "." in rd else 0, int("login" in rd)]


def load():
    with open(os.path.join(DATA_DIR, "openphish_urls.txt")) as f:
        phishing = [l.strip() for l in f if l.strip()]
    tranco = []
    with open(os.path.join(DATA_DIR, "tranco_domains.csv")) as f:
        for row in csv.reader(f):
            if len(row) == 2:
                tranco.append((int(row[0]), row[1].strip().lower()))
    urlhaus_hosts = set()
    with open(os.path.join(DATA_DIR, "urlhaus_data.csv"), encoding="utf-8") as f:
        for row in csv.reader(l for l in f if l.strip() and not l.startswith("#")):
            urlhaus_hosts.add(parse(row[2])[0])
    return phishing, tranco, urlhaus_hosts


def sample_tranco(tranco):
    rng = random.Random(SEED)
    tranco = sorted(tranco)
    sample = []
    for lo, hi in TIERS:
        tier = [t for t in tranco if lo < t[0] <= hi]
        sample += [(r, d, f"{lo // 1000}K-{hi // 1000}K") for r, d in rng.sample(tier, PER_TIER)]
    return sample


def class_metrics(y, p):
    pr, rc, f1, _ = precision_recall_fscore_support(y, p, labels=[0, 1], zero_division=0)
    return {"benign": {"precision": pr[0], "recall": rc[0], "f1": f1[0]},
            "phishing": {"precision": pr[1], "recall": rc[1], "f1": f1[1]}}


def evaluate(X, y, groups, train_idx, test_idx, model_factory):
    Xtr, ytr, gtr = X[train_idx], y[train_idx], groups[train_idx]
    cv = StratifiedGroupKFold(n_splits=10, shuffle=True, random_state=SEED)
    scores = []
    for a, b in cv.split(Xtr, ytr, gtr):
        m = model_factory().fit(Xtr[a], ytr[a])
        scores.append(accuracy_score(ytr[b], m.predict(Xtr[b])))
    scores = np.array(scores)
    sd = scores.std(ddof=1)
    half = stats.t.ppf(0.975, len(scores) - 1) * sd / np.sqrt(len(scores))
    model = model_factory().fit(Xtr, ytr)
    pred = model.predict(X[test_idx])
    return model, pred, {
        "cv_fold_accuracies": scores.round(4).tolist(),
        "cv_mean": scores.mean(), "cv_sd": sd,
        "cv_ci95": [scores.mean() - half, scores.mean() + half],
        "test_accuracy": accuracy_score(y[test_idx], pred),
        "test_confusion_matrix [[TN,FP],[FN,TP]]": confusion_matrix(y[test_idx], pred, labels=[0, 1]).tolist(),
        "test_class_metrics": class_metrics(y[test_idx], pred),
    }


def rf():
    return RandomForestClassifier(n_estimators=N_ESTIMATORS, max_depth=MAX_DEPTH,
                                  min_samples_split=MIN_SAMPLES_SPLIT, random_state=SEED)


def lr():
    return make_pipeline(StandardScaler(), LogisticRegression(max_iter=5000, random_state=SEED))


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    phishing, tranco, urlhaus_hosts = load()
    benign = sample_tranco(tranco)

    # Exact-duplicate removal and conflict checks.
    records = list(dict.fromkeys([(u, 1, "OpenPhish", "") for u in phishing] +
                                 [(d, 0, f"Tranco rank {r}", tier) for r, d, tier in benign]))
    n_dup = len(phishing) + len(benign) - len(records)
    threat_hosts = {parse(u)[0] for u in phishing} | urlhaus_hosts
    threat_rds = {registered_domain(h) for h in threat_hosts}
    benign_hosts = [parse(d)[0] for d, lab, *_ in records if lab == 0]
    conflicts_fqdn = sorted(h for h in benign_hosts if h in threat_hosts)
    conflicts_rd = sorted(h for h in benign_hosts if registered_domain(h) in threat_rds)

    urls = [r[0] for r in records]
    y = np.array([r[1] for r in records])
    groups = np.array([registered_domain(parse(u)[0]) for u in urls])
    X = np.array([extract_15_features(u) for u in urls], dtype=float)

    # Held-out partition: one fold of a 5-fold stratified group split (~20%).
    outer = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=SEED)
    train_idx, test_idx = next(outer.split(X, y, groups))
    assert not set(groups[train_idx]) & set(groups[test_idx])

    with open("dataset.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["record", "label", "source", "tranco_tier", "registered_domain", "partition"])
        part = np.array(["train"] * len(urls), dtype=object)
        part[test_idx] = "test"
        for (u, lab, src, tier), g, p in zip(records, groups, part):
            w.writerow([u, lab, src, tier, g, p])

    rf_model, rf_pred, rf_res = evaluate(X, y, groups, train_idx, test_idx, rf)
    _, _, lr_res = evaluate(X, y, groups, train_idx, test_idx, lr)

    Xd = np.array([domain_features(u) for u in urls], dtype=float)
    _, _, dom_res = evaluate(Xd, y, groups, train_idx, test_idx, rf)

    benign_path = sum(1 for u, lab in zip(urls, y) if lab == 0 and parse(u)[1] not in ("", "/"))
    phish_path = sum(1 for u, lab in zip(urls, y) if lab == 1 and parse(u)[1] not in ("", "/"))
    misclassified = [urls[i] for i, p in zip(test_idx, rf_pred) if p != y[i]]
    importances = dict(zip(FEATURES, rf_model.feature_importances_.round(4).tolist()))
    adhoc = {u: round(float(rf_model.predict_proba(np.array([extract_15_features(u)]))[0, 1]), 3)
             for u in ADHOC}

    out = {
        "sample": {"phishing": int((y == 1).sum()), "benign": int((y == 0).sum()),
                   "duplicates_removed": n_dup,
                   "benign_fqdn_conflicts_with_threat_feeds": conflicts_fqdn,
                   "benign_registered_domain_conflicts_with_threat_feeds": conflicts_rd,
                   "distinct_registered_domains": int(len(set(groups))),
                   "phishing_registered_domains": int(len(set(groups[y == 1]))),
                   "phishing_with_nonroot_path": phish_path, "benign_with_nonroot_path": benign_path},
        "partition": {"train": len(train_idx), "test": len(test_idx),
                      "test_benign": int((y[test_idx] == 0).sum()),
                      "test_phishing": int((y[test_idx] == 1).sum())},
        "random_forest_15_features": rf_res,
        "logistic_regression_15_features": lr_res,
        "random_forest_registered_domain_only": dom_res,
        "gini_importance": importances,
        "misclassified_test_records": misclassified,
        "adhoc_phishing_probability": adhoc,
    }
    with open(os.path.join(OUT_DIR, "results.json"), "w") as f:
        json.dump(out, f, indent=2, default=float)
    print(json.dumps(out, indent=2, default=float))
    make_figure(out, y)


def make_figure(out, y):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    ink, muted, c1, c2 = "#1f2933", "#6b7280", "#2563eb", "#d97706"
    plt.rcParams.update({"font.size": 9, "axes.edgecolor": muted, "axes.labelcolor": ink,
                         "xtick.color": ink, "ytick.color": ink})
    fig, ax = plt.subplots(2, 2, figsize=(11, 7.5))
    
    a = ax[0, 0]
    configs = [("RF, 15 features", out["random_forest_15_features"]),
               ("LR, 15 features", out["logistic_regression_15_features"]),
               ("RF, registered\ndomain only", out["random_forest_registered_domain_only"])]
    x = np.arange(len(configs))
    cvm = [r["cv_mean"] for _, r in configs]
    cve = [r["cv_ci95"][1] - r["cv_mean"] for _, r in configs]
    te = [r["test_accuracy"] for _, r in configs]
    a.bar(x - 0.19, cvm, 0.36, yerr=cve, capsize=3, color=c1, label="10-fold CV mean (95% CI)")
    a.bar(x + 0.19, te, 0.36, color=c2, label="Held-out accuracy")
    for xi, v, e in zip(x - 0.19, cvm, cve):
        a.text(xi, v + e + 0.02, f"{v * 100:.1f}", ha="center", fontsize=8)
    for xi, v in zip(x + 0.19, te):
        a.text(xi, v + 0.015, f"{v * 100:.1f}", ha="center", fontsize=8)
    maj = (y == 0).mean()
    a.axhline(maj, color=muted, ls="--", lw=1, label=f"Majority class ({maj * 100:.1f}%)")
    a.set_xticks(x, [n for n, _ in configs])
    a.set_ylim(0, 1.25)
    a.set_yticks(np.linspace(0, 1, 6))
    a.set_ylabel("Accuracy")
    a.set_title("(a) Accuracy by configuration (same partitions)", loc="left")
    a.legend(frameon=False, loc="upper right", ncol=2, fontsize=8)

    b = ax[0, 1]
    imp = sorted(out["gini_importance"].items(), key=lambda kv: kv[1])
    b.barh([k for k, _ in imp], [v for _, v in imp], color=c1)
    b.set_title("(b) Gini importance (identifiers of Table 6)", loc="left")
    b.set_xlabel("Mean decrease in impurity")

    c = ax[1, 0]
    p = out["partition"]
    tr_ph = int((y == 1).sum()) - p["test_phishing"]
    tr_bn = p["train"] - tr_ph
    c.bar(["Train", "Held-out"], [tr_bn, p["test_benign"]], width=0.5, color=c1, label="Benign (Tranco domains)")
    c.bar(["Train", "Held-out"], [tr_ph, p["test_phishing"]], width=0.5, bottom=[tr_bn, p["test_benign"]],
          color=c2, label="Phishing (OpenPhish URLs)")
    c.set_title("(c) Sample composition by partition", loc="left")
    c.set_ylabel("Records")
    c.set_xlim(-0.6, 1.6)
    c.set_ylim(0, 820)
    c.legend(frameon=False, loc="upper right")

    d = ax[1, 1]
    ad = list(out["adhoc_phishing_probability"].items())
    d.barh([u for u, _ in ad][::-1], [v for _, v in ad][::-1], color=muted)
    for i, (_, v) in enumerate(ad[::-1]):
        d.text(min(v + 0.02, 0.93), i, f"{v:.2f}", va="center", fontsize=8)
    d.set_xlim(0, 1)
    d.set_title("(d) Predicted phishing probability, 7 ad hoc examples", loc="left")
    for s in ax.flat:
        s.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(os.path.join(OUT_DIR, "ml_performance_analysis.png"), dpi=600)
    fig.savefig(os.path.join(OUT_DIR, "ml_performance_analysis.pdf"))


if __name__ == "__main__":
    main()
