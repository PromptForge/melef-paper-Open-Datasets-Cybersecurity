"""Descriptive measures of Table 5, computed on the snapshot files in paper_results/
(OpenPhish community feed, URLhaus recent-URLs CSV dump, Tranco top-1M list; all
retrieved on 6 August 2025 by download_real_datasets.py).

    python snapshot_measures.py   # writes results/snapshot_measures.json
"""
import csv, ipaddress, json, os, statistics, urllib.parse
import tldextract

D = os.environ.get("MELEF_DATA", "paper_results")
EX = tldextract.TLDExtract(suffix_list_urls=())


def parts(u):
    s = u if u.startswith(("http://", "https://")) else "http://" + u
    p = urllib.parse.urlparse(s)
    return p.scheme, p.netloc.split(":")[0].lower(), p.path, p.query


def rd(h):
    e = EX(h)
    return e.top_domain_under_public_suffix if hasattr(e, "top_domain_under_public_suffix") else e.registered_domain


def is_ip(h):
    try:
        ipaddress.ip_address(h.strip("[]"))
        return True
    except ValueError:
        return False


def measures(urls, has_scheme=True):
    P = [parts(u) for u in urls]
    hosts = [h for _, h, _, _ in P]
    names = [h for h in hosts if not is_ip(h)]
    out = {
        "records": len(urls),
        "distinct_records": len(set(urls)),
        "distinct_hostnames": len(set(hosts)),
        "records_with_ip_host": sum(1 for h in hosts if is_ip(h)),
        "distinct_registered_domains": len({rd(h) for h in names} - {""}),
        "distinct_tlds": len({h.rsplit(".", 1)[-1] for h in names if "." in h}),
        "nonroot_path": sum(1 for _, _, p, _ in P if p not in ("", "/")),
        "query_component": sum(1 for *_, q in P if q),
        "mean_string_length": round(statistics.mean(len(u) for u in urls), 2),
        "mean_hostname_length": round(statistics.mean(len(h) for h in hosts), 2),
    }
    if has_scheme:
        out["https"] = sum(1 for u in urls if u.startswith("https://"))
    return out


op = [l.strip() for l in open(os.path.join(D, "openphish_urls.txt")) if l.strip()]
uh_rows = list(csv.reader(l for l in open(os.path.join(D, "urlhaus_data.csv"), encoding="utf-8")
                          if l.strip() and not l.startswith("#")))
uh = [r[2] for r in uh_rows]
tr = [r[1] for r in csv.reader(open(os.path.join(D, "tranco_domains.csv"))) if len(r) == 2]

res = {"openphish": measures(op), "urlhaus": measures(uh), "tranco": measures(tr, has_scheme=False)}
res["urlhaus"]["dateadded_range"] = [min(r[1] for r in uh_rows), max(r[1] for r in uh_rows)]
res["urlhaus"]["threat_types"] = sorted({r[5] for r in uh_rows})
res["overlap"] = {
    "exact_url_openphish_urlhaus": len(set(op) & set(uh)),
    "hostname_openphish_urlhaus": len({parts(u)[1] for u in op} & {parts(u)[1] for u in uh}),
    "registered_domain_openphish_urlhaus": sorted(({rd(parts(u)[1]) for u in op} & {rd(parts(u)[1]) for u in uh}) - {""}),
    "tranco_domains_equal_to_openphish_hostname": len(set(tr) & {parts(u)[1] for u in op}),
    "tranco_domains_equal_to_urlhaus_hostname": len(set(tr) & {parts(u)[1] for u in uh}),
}
os.makedirs("results", exist_ok=True)
json.dump(res, open("results/snapshot_measures.json", "w"), indent=2)
print(json.dumps(res, indent=2))
