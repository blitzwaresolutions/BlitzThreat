#!/usr/bin/env python3
"""Build data/cve-snapshot.json from NVD, CISA KEV and FIRST EPSS (stdlib only).
Optional env: NVD_API_KEY (server-side only, never put it in the browser), BTEEM_DAYS (default 14)."""
import json, os, sys, time, urllib.parse, urllib.request
from datetime import datetime, timedelta, timezone

DAYS = int(os.environ.get("BTEEM_DAYS", "14"))
KEY = os.environ.get("NVD_API_KEY", "").strip()
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "cve-snapshot.json")
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS = "https://api.first.org/data/v1/epss"
MAX_ITEMS = 300
PAUSE = 0.8 if KEY else 6.5   # stay under NVD rate limits

def get(url, headers=None, tries=4):
    for n in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "BTEEM-snapshot/1.0", **(headers or {})})
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.load(r)
        except Exception as e:
            if n == tries - 1:
                raise
            print(f"retry {n + 1}: {e}", file=sys.stderr)
            time.sleep(10 * (n + 1))

def fmt(d): return d.strftime("%Y-%m-%dT%H:%M:%S.000")

def fetch_nvd(start, end):
    out, idx = [], 0
    while True:
        q = urllib.parse.urlencode({"pubStartDate": fmt(start), "pubEndDate": fmt(end),
                                    "resultsPerPage": 2000, "startIndex": idx})
        page = get(f"{NVD}?{q}", {"apiKey": KEY} if KEY else None)
        out += page.get("vulnerabilities", [])
        idx += page.get("resultsPerPage", 0)
        if idx >= page.get("totalResults", 0) or not page.get("resultsPerPage"):
            return out
        time.sleep(PAUSE)

def parse(v):
    c = v["cve"]
    desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
    score = sev = ver = vec = None
    for k, label in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        m = c.get("metrics", {}).get(k)
        if m:
            d = m[0].get("cvssData", {})
            score, ver, vec = d.get("baseScore"), label, d.get("vectorString")
            sev = (d.get("baseSeverity") or m[0].get("baseSeverity") or "").upper() or None
            break
    return {"id": c["id"], "published": c.get("published", "")[:10], "score": score,
            "severity": sev or "UNSCORED", "cvss": ver, "vector": vec, "desc": desc[:400],
            "kev": False, "epss": None}

def main():
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=DAYS)
    items = [parse(v) for v in fetch_nvd(start, end)]
    if not items:
        sys.exit("NVD returned no records; keeping the previous snapshot.")

    kev = get(KEV)["vulnerabilities"]
    kev_ids = {k["cveID"] for k in kev}
    cutoff = start.strftime("%Y-%m-%d")
    kev_recent = [{"id": k["cveID"], "name": k.get("vulnerabilityName", ""), "vendor": k.get("vendorProject", ""),
                   "product": k.get("product", ""), "added": k.get("dateAdded", "")}
                  for k in kev if k.get("dateAdded", "") >= cutoff]
    kev_recent.sort(key=lambda k: k["added"], reverse=True)

    for it in items:
        it["kev"] = it["id"] in kev_ids
    ids = [i["id"] for i in items]
    epss = {}
    for n in range(0, len(ids), 100):
        try:
            for r in get(f"{EPSS}?cve={','.join(ids[n:n + 100])}").get("data", []):
                epss[r["cve"]] = float(r["epss"])
        except Exception as e:
            print(f"EPSS batch skipped: {e}", file=sys.stderr)
    for it in items:
        it["epss"] = epss.get(it["id"])

    counts = {s: 0 for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNSCORED")}
    for it in items:
        counts[it["severity"] if it["severity"] in counts else "UNSCORED"] += 1
    items.sort(key=lambda i: (i["kev"], i["score"] or 0, i["epss"] or 0), reverse=True)

    snap = {"generated": end.strftime("%Y-%m-%dT%H:%M:%SZ"), "window_days": DAYS, "total": len(items),
            "counts": counts, "kev_in_window": sum(i["kev"] for i in items), "kev_recent": kev_recent[:25],
            "items": items[:MAX_ITEMS],
            "sources": ["NIST NVD API 2.0", "CISA Known Exploited Vulnerabilities", "FIRST EPSS"]}
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(snap, f, separators=(",", ":"))
    print(f"Wrote {len(snap['items'])} of {len(items)} CVEs to {os.path.normpath(OUT)}")

if __name__ == "__main__":
    main()
