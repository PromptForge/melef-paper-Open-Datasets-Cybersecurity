"""
Accessibility protocol (Gate 1) for manuscript electronics-4565560.

Implements the protocol described in Section 4.2: T = 5 bulk-retrieval attempts
per dataset at 12-hour intervals, 30-second timeout, a descriptive User-Agent,
exponential back-off on HTTP 429/5xx within an attempt, and a JSON-lines log of
every request. ASR = S / T x 100%, where an attempt succeeds only if the complete
file is downloaded with HTTP 200 and passes a format check.

NOTE: this file is a re-implementation of the documented protocol, released so
that the measurement can be repeated against current endpoints. See README.md
for its relationship to the May 2025 measurements reported in the manuscript.

Usage
    export PHISHTANK_APP_KEY=...            # optional; developer application key
    python accessibility_protocol.py --once         # one attempt per dataset now
    python accessibility_protocol.py --schedule     # 5 attempts, 12 h apart
    python accessibility_protocol.py --summarize    # ASR table from the log
"""
import argparse
import datetime as dt
import io
import json
import os
import time
import zipfile

import requests

USER_AGENT = os.environ.get(
    "MELEF_USER_AGENT",
    "AcademicResearch-MELEF-Client/1.0 "
    "(+https://github.com/PromptForge/melef-paper-Open-Datasets-Cybersecurity; "
    "contact: dkarapiperis@eap.gr)")
TIMEOUT = 30
ATTEMPTS = 5
INTERVAL_S = 12 * 3600
BACKOFF = [30, 60, 120]          # seconds, retries within one attempt
LOG = "results/accessibility_log.jsonl"


def phishtank_url():
    key = os.environ.get("PHISHTANK_APP_KEY")
    base = "http://data.phishtank.com/data/{}online-valid.csv"
    return base.format(f"{key}/" if key else "")


def check_openphish(body):
    lines = [l for l in body.decode("utf-8", "replace").splitlines() if l.strip()]
    return len(lines), all(l.startswith(("http://", "https://")) for l in lines[:50])


def check_urlhaus(body):
    text = body.decode("utf-8", "replace")
    rows = [l for l in text.splitlines() if l.strip() and not l.startswith("#")]
    return len(rows), text.lstrip().startswith("#") and "url" in text[:2000].lower()


def check_tranco(body):
    with zipfile.ZipFile(io.BytesIO(body)) as z:
        name = [n for n in z.namelist() if n.endswith(".csv")][0]
        rows = [l for l in z.read(name).decode().splitlines() if "," in l]
    return len(rows), len(rows) > 0


def check_phishtank(body):
    rows = body.decode("utf-8", "replace").splitlines()
    return max(0, len(rows) - 1), rows[:1] and rows[0].startswith("phish_id")


DATASETS = {
    "PhishTank": (phishtank_url, check_phishtank),
    "OpenPhish": (lambda: "https://openphish.com/feed.txt", check_openphish),
    "URLHaus": (lambda: "https://urlhaus.abuse.ch/downloads/csv_recent/", check_urlhaus),
    "Tranco": (lambda: "https://tranco-list.eu/top-1m.csv.zip", check_tranco),
}


def log(entry):
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    with open(LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")


def attempt(name, attempt_no):
    url_fn, check = DATASETS[name]
    url = url_fn()
    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT
    for retry in range(len(BACKOFF) + 1):
        t0 = dt.datetime.now(dt.timezone.utc)
        entry = {"dataset": name, "attempt": attempt_no, "retry": retry,
                 "utc": t0.isoformat(timespec="seconds"),
                 "url": url.replace(os.environ.get("PHISHTANK_APP_KEY", "\0"), "<key>"),
                 "user_agent": USER_AGENT}
        try:
            r = session.get(url, timeout=TIMEOUT)
            entry.update(status=r.status_code, bytes=len(r.content))
            if r.status_code == 200:
                records, ok = check(r.content)
                entry.update(records=records, format_ok=bool(ok), success=bool(ok))
                log(entry)
                return entry
            entry["success"] = False
            log(entry)
            if r.status_code not in (429, 500, 502, 503, 504):
                return entry
        except (requests.RequestException, zipfile.BadZipFile, IndexError) as e:
            entry.update(error=type(e).__name__, success=False)
            log(entry)
        if retry < len(BACKOFF):
            time.sleep(BACKOFF[retry])
    return entry


def run_round(attempt_no):
    for name in DATASETS:
        e = attempt(name, attempt_no)
        print(f"[{e['utc']}] {name:9s} attempt {attempt_no}: "
              f"status={e.get('status', e.get('error'))} success={e['success']}")


def summarize():
    final = {}
    for line in open(LOG):
        e = json.loads(line)
        final[(e["dataset"], e["attempt"])] = e      # last retry of each attempt
    print(f"{'Dataset':10s} {'T':>2s} {'S':>2s} {'ASR':>6s}  records (last success)")
    for name in DATASETS:
        att = [e for (d, _), e in final.items() if d == name]
        s = sum(e["success"] for e in att)
        rec = next((e.get("records") for e in reversed(att) if e["success"]), 0)
        print(f"{name:10s} {len(att):2d} {s:2d} {100 * s / max(1, len(att)):5.0f}%  {rec}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--once", action="store_true")
    g.add_argument("--schedule", action="store_true")
    g.add_argument("--summarize", action="store_true")
    a = ap.parse_args()
    if a.summarize:
        summarize()
    elif a.once:
        run_round(1)
    else:
        for i in range(1, ATTEMPTS + 1):
            run_round(i)
            if i < ATTEMPTS:
                time.sleep(INTERVAL_S)
