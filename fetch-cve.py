import json, os, sys, time, urllib.error, urllib.parse, urllib.request
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from validate_snapshot import validate, validate_kev, SEVS

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS = "https://api.first.org/data/v1/epss"
PUB_DAYS, MOD_DAYS = 14, 7        # keep CVEs published in 14 days or modified in 7
FULL_DAYS, MAX_RANGE = 30, 119    # reconcile window; NVD allows at most 120 days per query
MAX_ITEMS, TIMEOUT, REUSE_HOURS = 500, 45, 36
VOLATILE = {"generated", "attempted", "last_success", "last_nvd_sync", "fetched", "source_updated"}
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")

class IngestError(Exception):
    pass

def log(m): print(m, file=sys.stderr, flush=True)
def key(): return os.environ.get("NVD_API_KEY", "").strip()
def pause(): return 0.8 if key() else 6.5            # stay inside NVD's published rate limits
def iso(d): return d.strftime("%Y-%m-%dT%H:%M:%SZ")
def nvd_ts(d): return d.strftime("%Y-%m-%dT%H:%M:%S.000")   # NVD treats a missing offset as UTC

def get(url, headers=None, tries=4):
    """GET JSON with a timeout, retry/backoff and Retry-After support. Never logs headers (the API key)."""
    for n in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "BTEEM-ingest/2.0", **(headers or {})})
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code not in (403, 429, 500, 502, 503, 504) or n == tries - 1:
                raise
            try: wait = int(e.headers.get("Retry-After", 0))
            except (TypeError, ValueError): wait = 0
            log(f"HTTP {e.code} from {urllib.parse.urlparse(url).netloc}; retry {n + 1}")
            time.sleep(min(max(wait, 10 * (n + 1)), 120))
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
            if n == tries - 1:
                raise
            log(f"{type(e).__name__} from {urllib.parse.urlparse(url).netloc}; retry {n + 1}")
            time.sleep(10 * (n + 1))

def fetch_nvd(start, end):
    out, idx, ts = [], 0, None
    while True:
        q = urllib.parse.urlencode({"lastModStartDate": nvd_ts(start), "lastModEndDate": nvd_ts(end),
                                    "resultsPerPage": 2000, "startIndex": idx})
        page = get(f"{NVD}?{q}", {"apiKey": key()} if key() else None)
        ts = page.get("timestamp", ts)
        recs = page.get("vulnerabilities", [])
        out += recs
        idx += len(recs)
        if not recs or idx >= page.get("totalResults", 0):
            return out, ts
        time.sleep(pause())

def parse(v):
    c = v["cve"]
    desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
    if c.get("vulnStatus") == "Rejected" or desc.startswith("** REJECT **"):
        return None
    score = sev = ver = vec = None
    for k, label in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        m = c.get("metrics", {}).get(k)
        if m:
            d = m[0].get("cvssData", {})
            score = float(d["baseScore"]) if d.get("baseScore") is not None else None
            ver, vec = label, d.get("vectorString")
            sev = str(d.get("baseSeverity") or m[0].get("baseSeverity") or "").upper()
            break
    return {"id": c["id"], "published": c.get("published", "")[:10], "modified": c.get("lastModified", "")[:10],
            "score": score, "severity": sev if sev in SEVS else "UNSCORED", "cvss": ver, "vector": vec,
            "desc": desc[:400], "kev": False, "kev_added": None, "kev_due": None, "kev_ransomware": False,
            "epss": None, "epss_date": None}

def fetch_kev(now):
    d = get(KEV)
    entries = [{"id": k["cveID"], "vendor": k.get("vendorProject", ""), "product": k.get("product", ""),
                "name": k.get("vulnerabilityName", ""), "added": k.get("dateAdded", ""), "due": k.get("dueDate", ""),
                "ransomware": k.get("knownRansomwareCampaignUse") == "Known"} for k in d["vulnerabilities"]]
    return {"schema_version": 1, "catalog_version": d.get("catalogVersion"), "released": d.get("dateReleased"),
            "fetched": iso(now), "source": "CISA Known Exploited Vulnerabilities Catalog", "entries": entries}

def fetch_epss(ids):
    scores, bad, batches = {}, 0, 0
    for n in range(0, len(ids), 100):
        batches += 1
        try:
            for r in get(f"{EPSS}?cve={','.join(ids[n:n + 100])}").get("data", []):
                scores[r["cve"]] = (float(r["epss"]), r.get("date"))
        except Exception as e:
            bad += 1
            log(f"EPSS batch skipped: {type(e).__name__}")
    return scores, bad, batches

def build(prev, prev_kev, now, full=False):
    live = prev if prev and not prev.get("sample") and prev.get("items") else None
    reconcile = full or now.weekday() == 6
    days = FULL_DAYS if reconcile else PUB_DAYS
    if live and live.get("generated"):    # after an outage, widen the window so no gap is left
        last = datetime.strptime(live["generated"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        days = max(days, (now - last).days + 2)
    days = min(days, MAX_RANGE)
    try:
        recs, ts = fetch_nvd(now - timedelta(days=days), now)
    except Exception as e:
        raise IngestError(f"NVD retrieval failed ({type(e).__name__}: {e})") from e

    items = {}
    for v in recs:
        it = parse(v)
        if it and (it["id"] not in items or it["modified"] >= items[it["id"]]["modified"]):
            items[it["id"]] = it                                   # deduplicate by CVE id
    pub_cut = (now - timedelta(days=PUB_DAYS)).strftime("%Y-%m-%d")
    mod_cut = (now - timedelta(days=MOD_DAYS)).strftime("%Y-%m-%d")
    items = {k: v for k, v in items.items() if v["published"] >= pub_cut or v["modified"] >= mod_cut}
    src = {"nvd": {"status": "ok", "fetched": iso(now), "source_updated": ts, "count": len(items),
                   "message": f"{len(recs)} records modified in the last {days} days"}}
    old = {i["id"]: i for i in (live or {}).get("items", [])}

    try:
        catalog = fetch_kev(now)
        src["kev"] = {"status": "ok", "fetched": iso(now), "source_updated": catalog["released"],
                      "count": len(catalog["entries"]), "message": ""}
    except Exception as e:
        catalog = prev_kev if prev_kev and prev_kev.get("entries") else None
        src["kev"] = {"status": "stale" if catalog else "failed", "fetched": (catalog or {}).get("fetched"),
                      "source_updated": (catalog or {}).get("released"), "count": len((catalog or {}).get("entries", [])),
                      "message": f"KEV refresh failed ({type(e).__name__}); " + ("reusing the previous catalog" if catalog else "no KEV data")}
    kmap = {k["id"]: k for k in catalog["entries"]} if catalog else {}
    for it in items.values():
        k = kmap.get(it["id"])
        if k:
            it.update(kev=True, kev_added=k["added"], kev_due=k["due"], kev_ransomware=k["ransomware"])
        elif not catalog and it["id"] in old:
            it.update({f: old[it["id"]].get(f) for f in ("kev", "kev_added", "kev_due", "kev_ransomware")})

    scores, bad, batches = fetch_epss(list(items))
    for it in items.values():
        if it["id"] in scores:
            it["epss"], it["epss_date"] = scores[it["id"]]
        elif it["id"] in old:
            it["epss"], it["epss_date"] = old[it["id"]].get("epss"), old[it["id"]].get("epss_date")
    src["epss"] = {"status": "ok" if not bad else "failed" if bad == batches else "partial", "fetched": iso(now),
                   "source_updated": max((d for _, d in scores.values() if d), default=None),
                   "count": sum(i["epss"] is not None for i in items.values()),
                   "message": "" if not bad else f"{bad} of {batches} batches failed; earlier scores kept where available"}

    allitems = sorted(items.values(), key=lambda i: (i["kev"], i["score"] or 0, i["epss"] or 0), reverse=True)
    counts = {s: 0 for s in SEVS}
    by_day = {}
    day_cut = (now - timedelta(days=PUB_DAYS - 1)).strftime("%Y-%m-%d")
    for it in allitems:
        counts[it["severity"]] += 1
        if it["published"] >= day_cut:
            by_day.setdefault(it["published"], {s: 0 for s in SEVS})[it["severity"]] += 1
    kev_cut = (now - timedelta(days=PUB_DAYS)).strftime("%Y-%m-%d")
    kev_recent = sorted(({"id": k["id"], "name": k["name"], "vendor": k["vendor"], "product": k["product"],
                          "added": k["added"], "due": k["due"]} for k in (catalog or {}).get("entries", [])
                         if k["added"] >= kev_cut), key=lambda k: k["added"], reverse=True)[:25]
    snap = {"schema_version": 2, "sample": False, "generated": iso(now), "window_days": PUB_DAYS,
            "retention": {"published_days": PUB_DAYS, "modified_days": MOD_DAYS}, "total": len(allitems),
            "counts": counts, "by_day": dict(sorted(by_day.items())),
            "kev_in_window": sum(i["kev"] for i in allitems), "kev_recent": kev_recent,
            "meta": {"mode": "reconcile" if reconcile else "window", "lookback_days": days, "last_nvd_sync": iso(now)},
            "source_status": src,
            "sources": ["NIST NVD API 2.0", "CISA Known Exploited Vulnerabilities", "FIRST EPSS"],
            "items": allitems[:MAX_ITEMS]}
    return snap, catalog

def dump(obj, list_key):
    """Compact JSON, one record per line, so GitHub can preview and diff it."""
    j = lambda v: json.dumps(v, separators=(",", ":"), ensure_ascii=False)
    head = ",\n".join(f'"{k}":{j(v)}' for k, v in obj.items() if k != list_key)
    return "{\n" + head + f',\n"{list_key}":[\n' + ",\n".join(j(i) for i in obj[list_key]) + "\n]\n}\n"

def norm(o):
    if isinstance(o, dict): return {k: norm(v) for k, v in o.items() if k not in VOLATILE}
    if isinstance(o, list): return [norm(x) for x in o]
    return o

def atomic_write(path, text):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    with open(tmp, encoding="utf-8") as f:
        json.load(f)                      # re-read from disk: the file must parse before it goes live
    os.replace(tmp, path)

def load(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None

def write_status(path, status):
    old = load(path)
    if not (old and norm(old) == norm(status)):
        atomic_write(path, json.dumps(status, indent=1) + "\n")

def main():
    data = os.environ.get("BTEEM_DATA_DIR") or os.path.join(ROOT, "data")
    os.makedirs(data, exist_ok=True)
    sp, kp, tp = (os.path.join(data, f) for f in ("cve-snapshot.json", "kev-catalog.json", "ingest-status.json"))
    now = datetime.now(timezone.utc)
    prev, prev_kev = load(sp), load(kp)
    live = prev if prev and not prev.get("sample") and prev.get("items") else None
    try:
        snap, catalog = build(prev, prev_kev, now, full=os.environ.get("BTEEM_FULL") == "1")
        errs = validate(snap, prev=live)
        if catalog is not None and catalog is not prev_kev:
            errs += validate_kev(catalog)
        if errs:
            raise IngestError("validation failed: " + "; ".join(errs[:6]))
    except Exception as e:
        msg = str(e)[:400]
        log(f"INGEST FAILED: {msg}\nThe last known-good snapshot was left untouched.")
        write_status(tp, {"result": "failed", "attempted": iso(now), "message": msg,
                          "last_success": (live or {}).get("generated")})
        return 1
    if catalog is not None and catalog is not prev_kev and norm(catalog) != norm(prev_kev or {}):
        atomic_write(kp, dump(catalog, "entries"))
    fresh = False
    if live and live.get("generated"):
        age = now - datetime.strptime(live["generated"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        fresh = age < timedelta(hours=REUSE_HOURS)
    if live and fresh and norm(live) == norm(snap):
        log("No change since the last snapshot; nothing to publish.")
    else:
        atomic_write(sp, dump(snap, "items"))
        log(f"Published {len(snap['items'])} of {snap['total']} CVEs ({snap['meta']['mode']}, {snap['meta']['lookback_days']}-day window).")
    ok = all(s["status"] == "ok" for s in snap["source_status"].values())
    write_status(tp, {"result": "ok" if ok else "partial", "attempted": iso(now), "last_success": snap["generated"],
                      "message": "" if ok else "; ".join(s["message"] for s in snap["source_status"].values() if s["status"] != "ok"),
                      "sources": {k: v["status"] for k, v in snap["source_status"].items()}})
    return 0

if __name__ == "__main__":
    sys.exit(main())
