"""
Extended evaluation (Round 4) for manuscript electronics-4565560.

Replaces the bare-domain benign class with benign *full URLs* collected
independently of the threat feeds (Common Crawl), and adds a temporally
separated test set.

    python extended_evaluation.py collect     # network: Common Crawl, OpenPhish, Tranco
    python extended_evaluation.py evaluate    # offline: uses the collected files only

Experiment A (same period, matched representation)
  phishing: the 300 OpenPhish URLs of the 6 Aug 2025 snapshot (paper_results/)
  benign:   for each Tranco domain sampled in dataset.csv, one page URL with a non-root
            path captured by Common Crawl in crawl CC-MAIN-2025-33 (captures 2-15 Aug
            2025; HTTP 200, text/html; robots.txt and XML excluded). Domains without
            such a capture are replaced by randomly drawn domains of the same Tranco
            rank tier (paper_results/tranco_domains.csv) until 200 URLs per tier;
            replacements whose registered domain occurs in a threat feed are excluded.
  protocol: 15 features, models and hyperparameters of train_classifier.py;
            stratified, registered-domain-grouped 5-fold CV over all 900 records
            (seed 42); ROC-AUC, balanced accuracy, accuracy, per-class recall.

Experiment B (temporal separation)
  train:    all records of Experiment A (Aug 2025)
  test:     phishing = OpenPhish public feed retrieved at collection time (Nov 2026);
            benign   = page URLs from crawl CC-MAIN-2026-43 for domains sampled (same
                       three tiers, seed 43) from the Tranco list retrieved at collection
                       time, excluding every registered domain used in Experiment A or
                       present in a threat feed.
            Phishing test records whose registered domain occurs in the training data
            are removed, so no registered domain is shared between train and test.

Sensitivity conditions (both experiments)
  S1: phishing URLs with a root path removed (benign URLs are path-bearing by construction)
  S2: leading "www." stripped from all hostnames
  S3: S1 and S2

Outputs (results/):
  benign_cc_train.csv, benign_cc_test.csv, openphish_test.txt, tranco_test_top1m.csv.zip,
  collection_log.json, extended_results.json, extended_evaluation.png/.pdf
  (cluster_<crawl>.idx index caches are written during collection and are not released)
"""
import collections
import csv
import datetime as dt
import io
import json
import os
import random
import sys
import time
import urllib.parse
import zipfile

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import train_classifier as tc  # noqa: E402  (features, grouping, models, evaluation)

OUT = "results"
SEED = 42
UA = ("AcademicResearch-MELEF-Client/1.0 "
      "(+https://github.com/PromptForge/melef-paper-Open-Datasets-Cybersecurity; "
      "contact: dkarapiperis@eap.gr)")
SNAPSHOT_DATE = dt.date(2025, 8, 6)


# --------------------------------------------------------------------------- network
# Common Crawl URL index, read directly from data.commoncrawl.org (ZipNum CDX):
# cluster.idx maps SURT-key ranges to compressed blocks of the cdx-*.gz files;
# each block is fetched with an HTTP Range request. This is the same lookup the
# index server (index.commoncrawl.org) performs.
CC_BASE = "https://data.commoncrawl.org/cc-index/collections/{crawl}/indexes/"
CRAWL_TRAIN = "CC-MAIN-2025-33"   # crawl closest to the 6 Aug 2025 snapshot
CRAWL_TEST = "CC-MAIN-2026-43"    # most recent crawl at collection time (Nov 2026)
MAX_BLOCKS = 3                    # compressed blocks read per domain


def http_get(url, timeout=120, retries=4, headers=None):
    import requests
    h = {"User-Agent": UA}
    h.update(headers or {})
    for i in range(retries):
        try:
            r = requests.get(url, headers=h, timeout=timeout)
            if r.status_code in (200, 206):
                return r
            if r.status_code in (429, 500, 502, 503, 504):
                time.sleep(5 * (2 ** i))
                continue
            return r
        except Exception:
            time.sleep(5 * (2 ** i))
    return None


def surt_prefixes(domain):
    parts = domain.lower().strip(".").split(".")[::-1]
    host = ",".join(parts)
    return [host + ")", host + ","]          # exact host, and its subdomains


class ZipNumIndex:
    def __init__(self, crawl):
        import bisect  # noqa: F401
        self.crawl = crawl
        path = os.path.join(OUT, f"cluster_{crawl}.idx")
        if not os.path.exists(path):
            r = http_get(CC_BASE.format(crawl=crawl) + "cluster.idx", timeout=600)
            with open(path, "wb") as f:
                f.write(r.content)
        self.keys, self.loc = [], []
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                key_ts, fname, off, length, _ = line.rstrip("\n").split("\t")
                self.keys.append(key_ts.split(" ")[0])
                self.loc.append((fname, int(off), int(length)))

    def blocks(self, prefix):
        import bisect
        i = max(0, bisect.bisect_left(self.keys, prefix) - 1)
        out = []
        while i < len(self.keys) and self.keys[i] <= prefix + "\uffff":
            out.append(i)
            i += 1
        return out

    def records(self, block_idx):
        import gzip
        fname, off, length = self.loc[block_idx]
        r = http_get(CC_BASE.format(crawl=self.crawl) + fname,
                     headers={"Range": f"bytes={off}-{off + length - 1}"})
        if r is None or r.status_code not in (200, 206):
            return []
        return gzip.decompress(r.content).decode("utf-8", "replace").splitlines()


def cc_page_url(index, domain, rng):
    """One captured page URL (non-root path, HTTP 200, HTML) for a registrable domain."""
    caps, seen_blocks = [], set()
    for prefix in surt_prefixes(domain):
        blocks = [b for b in index.blocks(prefix) if b not in seen_blocks]
        if len(blocks) > MAX_BLOCKS:
            blocks = sorted(rng.sample(blocks, MAX_BLOCKS))
        for b in blocks:
            seen_blocks.add(b)
            for line in index.records(b):
                key, _, rest = line.partition(" ")
                if not key.startswith(prefix):
                    continue
                try:
                    c = json.loads(rest.split(" ", 1)[1])
                except (IndexError, ValueError):
                    continue
                mime = c.get("mime-detected") or c.get("mime", "")
                u = c.get("url", "")
                path = urllib.parse.urlparse(u).path
                if (c.get("status") == "200" and mime.startswith("text/html")
                        and path not in ("", "/") and not path.lower().endswith(("robots.txt", ".xml"))):
                    caps.append({"url": u, "timestamp": rest.split(" ", 1)[0]})
    if not caps:
        return None, 0
    caps = sorted({c["url"]: c for c in caps}.values(), key=lambda c: c["url"])
    return rng.choice(caps), len(caps)


def collect_benign(candidates, crawl, rng, label, quota=None):
    """candidates: list of (domain, tier) in the order to try. With a quota, domains
    without a usable capture are replaced by the next candidate of the same tier
    until `quota` URLs per tier are collected."""
    index = ZipNumIndex(crawl)
    rows, tried, missing = [], 0, []
    count = {}
    for d, tier in candidates:
        if quota is not None and count.get(tier, 0) >= quota:
            continue
        tried += 1
        cap, n = cc_page_url(index, d, rng)
        if cap is None:
            missing.append(d)
        else:
            count[tier] = count.get(tier, 0) + 1
            rows.append({"domain": d, "tier": tier, "url": cap["url"], "timestamp": cap["timestamp"],
                         "captures_considered": n, "crawl": crawl})
        if tried % 100 == 0:
            print(f"  [{label}] tried {tried}, collected {len(rows)} {count}", flush=True)
        if quota is not None and all(count.get(t, 0) >= quota for t in {t for _, t in candidates}):
            break
    return rows, tried, missing


def tier_of(rank):
    for lo, hi in tc.TIERS:
        if lo < rank <= hi:
            return f"{lo // 1000}K-{hi // 1000}K"
    return None


def candidates(primary, pool, rng, exclude_rd):
    """Primary domains first (in their tier), then shuffled replacements per tier."""
    out = list(primary)
    used = {d for d, _ in primary}
    by_tier = {}
    for rank, d in pool:
        t = tier_of(rank)
        if t and d not in used and tc.registered_domain(d) not in exclude_rd:
            by_tier.setdefault(t, []).append(d)
    for t in sorted(by_tier):
        reps = by_tier[t]
        rng.shuffle(reps)
        out += [(d, t) for d in reps[:3000]]
    return out


def write_csv(path, rows):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


def collect():
    os.makedirs(OUT, exist_ok=True)
    log = {"collected_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
           "user_agent": UA, "crawl_train": CRAWL_TRAIN, "crawl_test": CRAWL_TEST,
           "replacement_rule": "domains without an HTML capture with a non-root path are replaced by "
                               "randomly drawn domains of the same Tranco rank tier until 200 per tier"}

    # Threat-feed domains (Aug 2025 snapshot) are excluded from the benign replacements
    snap_ph = [l.strip() for l in open(os.path.join(tc.DATA_DIR, "openphish_urls.txt")) if l.strip()]
    threat_rd = {tc.registered_domain(tc.parse(u)[0]) for u in snap_ph}
    with open(os.path.join(tc.DATA_DIR, "urlhaus_data.csv"), encoding="utf-8") as f:
        for row in csv.reader(l for l in f if l.strip() and not l.startswith("#")):
            threat_rd.add(tc.registered_domain(tc.parse(row[2])[0]))

    # Experiment A benign: the 600 Tranco domains of dataset.csv, replacements from the same list
    with open("dataset.csv") as f:
        prim = [(r["record"], r["tranco_tier"]) for r in csv.DictReader(f) if r["label"] == "0"]
    pool = [(int(a), b.strip().lower()) for a, b in
            csv.reader(open(os.path.join(tc.DATA_DIR, "tranco_domains.csv"))) if a.strip().isdigit()]
    cand = candidates(prim, pool, random.Random(SEED), threat_rd)
    rows, tried, miss = collect_benign(cand, CRAWL_TRAIN, random.Random(SEED), "train", quota=tc.PER_TIER)
    write_csv(os.path.join(OUT, "benign_cc_train.csv"), rows)
    log["benign_train"] = {"urls": len(rows), "domains_tried": tried, "domains_without_capture": len(miss),
                           "original_sample_domains_used": sum(1 for r in rows if r["domain"] in {d for d, _ in prim})}

    # Experiment B: fresh OpenPhish feed and fresh Tranco list
    r = http_get("https://openphish.com/feed.txt")
    feed = [l.strip() for l in r.text.splitlines() if l.strip()]
    with open(os.path.join(OUT, "openphish_test.txt"), "w") as f:
        f.write("\n".join(feed) + "\n")
    log["openphish_test"] = {"urls": len(feed), "status": r.status_code, "final_url": r.url,
                             "redirects": [h.headers.get("Location") for h in r.history]}

    r = http_get("https://tranco-list.eu/top-1m.csv.zip", timeout=300)
    with open(os.path.join(OUT, "tranco_test_top1m.csv.zip"), "wb") as f:
        f.write(r.content)
    with zipfile.ZipFile(io.BytesIO(r.content)) as z:
        name = [n for n in z.namelist() if n.endswith(".csv")][0]
        tranco = [(int(a), b.strip().lower()) for a, b in csv.reader(io.StringIO(z.read(name).decode()))]
    log["tranco_test"] = {"final_url": r.url, "size": len(tranco)}
    exclude = {tc.registered_domain(r["domain"]) for r in rows} | threat_rd | \
              {tc.registered_domain(tc.parse(u)[0]) for u in feed}
    cand = candidates([], tranco, random.Random(SEED + 1), exclude)
    trows, tried, miss = collect_benign(cand, CRAWL_TEST, random.Random(SEED + 1), "test", quota=tc.PER_TIER)
    write_csv(os.path.join(OUT, "benign_cc_test.csv"), trows)
    log["benign_test"] = {"urls": len(trows), "domains_tried": tried, "domains_without_capture": len(miss)}

    # URLhaus endpoint used for the Aug 2025 snapshot (accessibility re-check only)
    r = http_get("https://urlhaus.abuse.ch/downloads/csv_recent/", retries=1)
    log["urlhaus_csv_recent_status"] = None if r is None else r.status_code

    with open(os.path.join(OUT, "collection_log.json"), "w") as f:
        json.dump(log, f, indent=2)
    print(json.dumps(log, indent=2))


# --------------------------------------------------------------------------- evaluation
def load_rows(path):
    with open(path) as f:
        return list(csv.DictReader(f))


def metrics(y, pred, proba=None):
    from sklearn.metrics import accuracy_score, roc_auc_score
    out = {"n": int(len(y)), "accuracy": float(accuracy_score(y, pred)),
           "confusion_matrix [[TN,FP],[FN,TP]]": tc.confusion_matrix(y, pred, labels=[0, 1]).tolist(),
           "class_metrics": tc.class_metrics(y, pred)}
    if proba is not None and len(set(y)) == 2:
        out["roc_auc"] = float(roc_auc_score(y, proba))
    return out


def describe(urls, y):
    def frac(cond, lab):
        idx = [i for i in range(len(urls)) if y[i] == lab]
        return round(sum(cond(urls[i]) for i in idx) / max(1, len(idx)), 4)
    d = {}
    for lab, name in [(0, "benign"), (1, "phishing")]:
        d[name] = {"n": int(sum(1 for v in y if v == lab)),
                   "https_share": frac(lambda u: u.startswith("https://"), lab),
                   "query_share": frac(lambda u: "?" in u, lab),
                   "mean_url_len": round(float(np.mean([len(urls[i]) for i in range(len(urls)) if y[i] == lab])), 2),
                   "mean_path_levels": round(float(np.mean([tc.extract_15_features(urls[i])[13]
                                                            for i in range(len(urls)) if y[i] == lab])), 2)}
    return d


def outer_cv(X, y, groups):
    """Grouped stratified 5-fold outer CV: every record is held out exactly once."""
    from sklearn.metrics import accuracy_score, balanced_accuracy_score, recall_score, roc_auc_score
    from sklearn.model_selection import StratifiedGroupKFold
    out = {}
    folds = list(StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=SEED).split(X, y, groups))
    for name, factory in [("random_forest_15_features", tc.rf), ("logistic_regression_15_features", tc.lr),
                          ("random_forest_special_slash_only", tc.rf)]:
        cols = [3] if name.endswith("slash_only") else list(range(X.shape[1]))
        per = {"accuracy": [], "balanced_accuracy": [], "roc_auc": [], "phishing_recall": [], "benign_recall": []}
        for tr, te in folds:
            m = factory().fit(X[tr][:, cols], y[tr])
            p = m.predict(X[te][:, cols])
            pr = m.predict_proba(X[te][:, cols])[:, 1]
            per["accuracy"].append(accuracy_score(y[te], p))
            per["balanced_accuracy"].append(balanced_accuracy_score(y[te], p))
            per["roc_auc"].append(roc_auc_score(y[te], pr))
            per["phishing_recall"].append(recall_score(y[te], p, pos_label=1))
            per["benign_recall"].append(recall_score(y[te], p, pos_label=0))
        out[name] = {k: {"mean": float(np.mean(v)), "sd": float(np.std(v, ddof=1)),
                         "folds": [round(float(x), 4) for x in v]} for k, v in per.items()}
    out["majority_class_accuracy"] = float((y == 0).mean())
    return out


def strip_www(u):
    scheme, sep, rest = u.partition("://")
    if not sep:
        return u[4:] if u.lower().startswith("www.") else u
    return scheme + sep + (rest[4:] if rest.lower().startswith("www.") else rest)


CONDITIONS = {
    # name: (keep phishing URLs without a path, keep a leading "www.")
    "base": (True, True),
    "S1_path_bearing_only": (False, True),
    "S2_www_removed": (True, False),
    "S3_path_bearing_and_www_removed": (False, False),
}


def build(phishing, benign, keep_root, keep_www):
    f = (lambda u: u) if keep_www else strip_www
    P = [f(u) for u in phishing if keep_root or tc.parse(u)[1] not in ("", "/")]
    B = [f(u) for u in benign]
    urls = list(dict.fromkeys(P + B))
    pos = set(P)
    y = np.array([1 if u in pos else 0 for u in urls])
    X = np.array([tc.extract_15_features(u) for u in urls], dtype=float)
    groups = np.array([tc.registered_domain(tc.parse(u)[0]) for u in urls])
    return urls, X, y, groups


def evaluate():
    from sklearn.metrics import balanced_accuracy_score
    phishing = [l.strip() for l in open(os.path.join(tc.DATA_DIR, "openphish_urls.txt")) if l.strip()]
    benign = [r["url"] for r in load_rows(os.path.join(OUT, "benign_cc_train.csv"))]
    test_ph_all = [l.strip() for l in open(os.path.join(OUT, "openphish_test.txt")) if l.strip()]
    test_bn_all = [r["url"] for r in load_rows(os.path.join(OUT, "benign_cc_test.csv"))]

    urls, X, y, groups = build(phishing, benign, True, True)
    train_rd = set(groups)
    test_ph = [u for u in dict.fromkeys(test_ph_all) if tc.registered_domain(tc.parse(u)[0]) not in train_rd]
    test_bn = [u for u in dict.fromkeys(test_bn_all) if tc.registered_domain(tc.parse(u)[0]) not in train_rd]
    removed = collections.Counter(tc.registered_domain(tc.parse(u)[0]) for u in test_ph_all
                                  if tc.registered_domain(tc.parse(u)[0]) in train_rd)

    rf_full = tc.rf().fit(X, y)
    res = {"experiment_A": {"description": describe(urls, y),
                            "gini_importance": dict(zip(tc.FEATURES, rf_full.feature_importances_.round(4).tolist()))},
           "experiment_B": {"phishing_retrieved": len(test_ph_all), "phishing_kept": len(test_ph),
                            "phishing_removed_shared_registered_domain": dict(removed.most_common()),
                            "benign_kept": len(test_bn),
                            "description": describe(test_ph + test_bn, np.array([1] * len(test_ph) + [0] * len(test_bn)))}}
    for cname, (keep_root, keep_www) in CONDITIONS.items():
        _, Xc, yc, gc = build(phishing, benign, keep_root, keep_www)
        res["experiment_A"][cname] = outer_cv(Xc, yc, gc)
        res["experiment_A"][cname]["n"] = int(len(yc))
        res["experiment_A"][cname]["n_phishing"] = int(yc.sum())
        _, TX, ty, _ = build(test_ph, test_bn, keep_root, keep_www)
        out = {"n": int(len(ty)), "n_phishing": int(ty.sum()),
               "majority_class_accuracy": float(max((ty == 0).mean(), (ty == 1).mean()))}
        for name, factory in [("random_forest_15_features", tc.rf), ("logistic_regression_15_features", tc.lr)]:
            m = factory().fit(Xc, yc)
            p = m.predict(TX)
            out[name] = metrics(ty, p, m.predict_proba(TX)[:, 1])
            out[name]["balanced_accuracy"] = float(balanced_accuracy_score(ty, p))
        res["experiment_B"][cname] = out

    with open(os.path.join(OUT, "extended_results.json"), "w") as f:
        json.dump(res, f, indent=2, default=float)
    print(json.dumps(res, indent=2, default=float))
    figure(res)


def figure(res):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    ink, muted, c1, c2 = "#1f2933", "#6b7280", "#2563eb", "#d97706"
    plt.rcParams.update({"font.size": 9, "axes.edgecolor": muted, "axes.labelcolor": ink,
                         "xtick.color": ink, "ytick.color": ink})
    A, B = res["experiment_A"], res["experiment_B"]
    fig, ax = plt.subplots(1, 3, figsize=(14, 4.4), gridspec_kw={"width_ratios": [1.25, 0.9, 1.1]})

    def bars(axis, labels, auc, auc_err, bal, bal_err, title):
        x = np.arange(len(labels))
        ae = auc_err if any(auc_err) else None
        be = bal_err if any(bal_err) else None
        axis.bar(x - 0.19, auc, 0.36, yerr=ae, capsize=3, color=c1, label="ROC-AUC")
        axis.bar(x + 0.19, bal, 0.36, yerr=be, capsize=3, color=c2, label="Balanced accuracy")
        for xi, v, e in zip(x - 0.19, auc, auc_err):
            axis.text(xi, v + (e or 0) + 0.02, f"{v:.2f}", ha="center", fontsize=7.5)
        for xi, v, e in zip(x + 0.19, bal, bal_err):
            axis.text(xi, v + (e or 0) + 0.02, f"{v:.2f}", ha="center", fontsize=7.5)
        axis.axhline(0.5, color=muted, ls="--", lw=1, label="Chance (0.5)")
        axis.set_xticks(x, labels)
        axis.set_ylim(0, 1.3)
        axis.set_yticks(np.linspace(0, 1, 6))
        axis.legend(frameon=False, loc="upper right", fontsize=7.5, ncol=3)
        axis.set_title(title, loc="left")

    cfg = [("RF", "base", "random_forest_15_features"), ("LR", "base", "logistic_regression_15_features"),
           ("RF,\nspecial_/ only", "base", "random_forest_special_slash_only"),
           ("RF, strict\n(S3)", "S3_path_bearing_and_www_removed", "random_forest_15_features")]
    g = lambda c, k, m: A[c][k][m]
    bars(ax[0], [c[0] for c in cfg],
         [g(c[1], c[2], "roc_auc")["mean"] for c in cfg], [g(c[1], c[2], "roc_auc")["sd"] for c in cfg],
         [g(c[1], c[2], "balanced_accuracy")["mean"] for c in cfg],
         [g(c[1], c[2], "balanced_accuracy")["sd"] for c in cfg],
         "(a) Exp. A, Aug 2025: grouped 5-fold CV (mean, SD)")

    b = ax[1]
    imp = sorted(A["gini_importance"].items(), key=lambda kv: kv[1])
    b.barh([k for k, _ in imp], [v for _, v in imp], color=c1)
    b.set_xlabel("Mean decrease in impurity")
    b.set_title("(b) Exp. A: Gini importance (RF)", loc="left")

    cfgB = [("RF", "base", "random_forest_15_features"), ("LR", "base", "logistic_regression_15_features"),
            ("RF, strict\n(S3)", "S3_path_bearing_and_www_removed", "random_forest_15_features"),
            ("LR, strict\n(S3)", "S3_path_bearing_and_www_removed", "logistic_regression_15_features")]
    bars(ax[2], [c[0] for c in cfgB],
         [B[c[1]][c[2]]["roc_auc"] for c in cfgB], [0] * 4,
         [B[c[1]][c[2]]["balanced_accuracy"] for c in cfgB], [0] * 4,
         "(c) Exp. B: train Aug 2025, test Nov 2026")
    for s_ in ax:
        s_.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, "extended_evaluation.png"), dpi=600)
    fig.savefig(os.path.join(OUT, "extended_evaluation.pdf"))


if __name__ == "__main__":
    {"collect": collect, "evaluate": evaluate}[sys.argv[1]]()
