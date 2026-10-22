#!/usr/bin/env python3
"""Schema and integrity checks for the BTEEM snapshot and KEV catalog (stdlib only).
CLI: python scripts/validate_snapshot.py data/cve-snapshot.json [data/kev-catalog.json]"""
import json, re, sys

ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
SEVS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNSCORED")
REQUIRED = ("schema_version", "sample", "generated", "total", "counts", "by_day",
            "kev_in_window", "kev_recent", "items", "source_status")
MIN_TOTAL = 50      # a 14-day window always holds far more than this; fewer means a bad pull
MIN_KEV = 500       # the real KEV catalog holds well over 1,000 entries
MAX_ERRORS = 50

def _num(x, lo, hi):
    return isinstance(x, (int, float)) and not isinstance(x, bool) and lo <= x <= hi

def validate(s, prev=None, min_total=MIN_TOTAL):
    """Return a list of problems; an empty list means the snapshot may be published."""
    if not isinstance(s, dict):
        return ["snapshot is not a JSON object"]
    e = [f"missing key: {k}" for k in REQUIRED if k not in s]
    if e:
        return e
    if s["schema_version"] != 2:
        e.append("schema_version must be 2")
    if s["sample"] is not False:
        e.append("a live snapshot must have sample=false")
    if not isinstance(s["items"], list):
        return e + ["items is not a list"]
    seen = set()
    for n, i in enumerate(s["items"]):
        if len(e) >= MAX_ERRORS:
            break
        if not isinstance(i, dict):
            e.append(f"item {n} is not an object"); continue
        cid = i.get("id")
        if not (isinstance(cid, str) and ID_RE.match(cid)):
            e.append(f"item {n}: bad CVE id {cid!r}"); continue
        if cid in seen:
            e.append(f"duplicate id {cid}")
        seen.add(cid)
        if i.get("severity") not in SEVS:
            e.append(f"{cid}: bad severity {i.get('severity')!r}")
        if i.get("score") is not None and not _num(i["score"], 0, 10):
            e.append(f"{cid}: score out of range")
        if i.get("epss") is not None and not _num(i["epss"], 0, 1):
            e.append(f"{cid}: epss out of range")
        for f in ("published", "modified"):
            if not DATE_RE.match(str(i.get(f, ""))):
                e.append(f"{cid}: bad {f} date")
        if not isinstance(i.get("kev"), bool):
            e.append(f"{cid}: kev must be true or false")
        if not isinstance(i.get("desc"), str):
            e.append(f"{cid}: desc must be text")
    c = s["counts"]
    if not (isinstance(c, dict) and all(isinstance(c.get(k), int) for k in SEVS)):
        e.append("counts must hold an integer for every severity")
    elif sum(c[k] for k in SEVS) != s["total"]:
        e.append("counts do not add up to total")
    if not isinstance(s["total"], int) or s["total"] < len(s["items"]):
        e.append("total is smaller than the number of items")
    elif s["total"] < min_total:
        e.append(f"only {s['total']} CVEs retrieved (minimum {min_total}); refusing to publish")
    if not isinstance(s["by_day"], dict) or not all(DATE_RE.match(k) for k in s["by_day"]):
        e.append("by_day must map dates to counts")
    if not isinstance(s["kev_recent"], list) or not isinstance(s["source_status"], dict):
        e.append("kev_recent must be a list and source_status an object")
    if prev and isinstance(prev.get("total"), int) and prev["total"] >= 100 \
            and isinstance(s["total"], int) and s["total"] < prev["total"] * 0.4:
        e.append(f"total fell from {prev['total']} to {s['total']}; looks like an incomplete pull")
    return e[:MAX_ERRORS]

def validate_kev(k, min_entries=MIN_KEV):
    if not isinstance(k, dict) or not isinstance(k.get("entries"), list):
        return ["KEV catalog must be an object with an entries list"]
    e, seen = [], set()
    if len(k["entries"]) < min_entries:
        e.append(f"KEV catalog has only {len(k['entries'])} entries (minimum {min_entries})")
    for n, x in enumerate(k["entries"]):
        if len(e) >= MAX_ERRORS:
            break
        cid = x.get("id") if isinstance(x, dict) else None
        if not (isinstance(cid, str) and ID_RE.match(cid)):
            e.append(f"KEV entry {n}: bad id {cid!r}"); continue
        if cid in seen:
            e.append(f"KEV duplicate {cid}")
        seen.add(cid)
        if not DATE_RE.match(str(x.get("added", ""))):
            e.append(f"KEV {cid}: bad added date")
        if x.get("due") and not DATE_RE.match(str(x["due"])):
            e.append(f"KEV {cid}: bad due date")
    return e

if __name__ == "__main__":
    bad = False
    for path in sys.argv[1:] or ["data/cve-snapshot.json"]:
        try:
            obj = json.load(open(path, encoding="utf-8"))
        except Exception as ex:
            print(f"{path}: not valid JSON ({ex})"); bad = True; continue
        errs = validate_kev(obj) if "entries" in obj else validate(obj)
        print(f"{path}: {'OK' if not errs else 'FAILED'}")
        for x in errs: print("  -", x)
        bad = bad or bool(errs)
    sys.exit(1 if bad else 0)
