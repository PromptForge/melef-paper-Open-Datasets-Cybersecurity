"""Figure 1 of manuscript electronics-4565560: characteristics of the analysed snapshots.

Computed from the files in paper_results/ (retrieved 6 August 2025):

    python make_figure1.py     # writes results/dataset_characteristics_analysis.png
"""
import collections
import csv
import ipaddress
import os
import urllib.parse

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker

D = os.environ.get("MELEF_DATA", "paper_results")
INK, MUTED, C1, C2, C3 = "#1f2933", "#6b7280", "#2563eb", "#d97706", "#059669"


def host(u):
    s = u if u.startswith(("http://", "https://")) else "http://" + u
    return urllib.parse.urlparse(s).netloc.split(":")[0].lower()


def is_ip(h):
    try:
        ipaddress.ip_address(h.strip("[]"))
        return True
    except ValueError:
        return False


op = [l.strip() for l in open(os.path.join(D, "openphish_urls.txt")) if l.strip()]
uh = [r for r in csv.reader(l for l in open(os.path.join(D, "urlhaus_data.csv"), encoding="utf-8")
                            if l.strip() and not l.startswith("#"))]
tr = [r[1].strip().lower() for r in csv.reader(open(os.path.join(D, "tranco_domains.csv"))) if len(r) == 2]

plt.rcParams.update({"font.size": 9, "axes.edgecolor": MUTED, "axes.labelcolor": INK,
                     "xtick.color": INK, "ytick.color": INK})
fig, ax = plt.subplots(2, 2, figsize=(11, 7.5))

# (a) OpenPhish scheme
https = sum(u.startswith("https://") for u in op)
http = len(op) - https
a = ax[0, 0]
a.barh(["HTTPS", "HTTP"], [https, http], color=[C1, C2])
for i, v in enumerate([https, http]):
    a.text(v + 3, i, f"{v} ({100 * v / len(op):.1f}%)", va="center", fontsize=8)
a.invert_yaxis()
a.set_xlim(0, len(op) * 1.2)
a.set_xlabel("URLs")
a.set_title(f"(a) OpenPhish: URL scheme (n = {len(op):,})", loc="left")

# (b) URLHaus tags and host type
tags = collections.Counter(t for r in uh for t in r[6].split(",") if t)
top = tags.most_common(6)
ip_hosts = sum(is_ip(host(r[2])) for r in uh)
labels = [f"tag: {t}" for t, _ in top] + ["host is an IP address"]
vals = [100 * n / len(uh) for _, n in top] + [100 * ip_hosts / len(uh)]
b = ax[0, 1]
b.barh(labels, vals, color=[C2] * len(top) + [MUTED])
for i, v in enumerate(vals):
    b.text(v + 1, i, f"{v:.1f}%", va="center", fontsize=8)
b.invert_yaxis()
b.set_xlim(0, 105)
b.set_xlabel("Share of records (%)")
b.set_title(f"(b) URLHaus: most frequent tags and host type (n = {len(uh):,})", loc="left")

# (c) Tranco top TLDs
tlds = collections.Counter(d.rsplit(".", 1)[-1] for d in tr if "." in d)
t10 = tlds.most_common(10)
c = ax[1, 0]
c.bar([f".{t}" for t, _ in t10], [n for _, n in t10], color=C3)
c.set_ylabel("Domains")
c.set_title(f"(c) Tranco: ten most frequent of {len(tlds):,} TLDs (n = {len(tr):,})", loc="left")
c.yaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda v, _: f"{int(v):,}"))
for lab in c.get_xticklabels():
    lab.set_rotation(45)

# (d) Dataset scale
d = ax[1, 1]
names, sizes = ["OpenPhish", "URLHaus", "Tranco"], [len(op), len(uh), len(tr)]
d.bar(names, sizes, color=[C1, C2, C3])
d.set_yscale("log")
for i, v in enumerate(sizes):
    d.text(i, v * 1.15, f"{v:,}", ha="center", fontsize=8)
d.set_ylim(100, 5e6)
d.set_ylabel("Records (log scale)")
d.set_title(f"(d) Records per snapshot (total {sum(sizes):,})", loc="left")

for s in ax.flat:
    s.spines[["top", "right"]].set_visible(False)
fig.tight_layout()
os.makedirs("results", exist_ok=True)
fig.savefig("results/dataset_characteristics_analysis.png", dpi=600)
fig.savefig("results/dataset_characteristics_analysis.pdf")
print("top tags", top, "ip", ip_hosts, "top tlds", t10, "total", sum(sizes))
