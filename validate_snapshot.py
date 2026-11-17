#!/usr/bin/env python3
# BTEEM_BASE2_111626a
"""Schema and integrity checks for the BTEEM snapshot and KEV catalog (stdlib only).
CLI: python scripts/validate_snapshot.py data/cve-snapshot.json [data/kev-catalog.json]"""
import json, re, sys
from datetime import datetime, timedelta, timezone

ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
SEVS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNSCORED")
SOURCES = ("nvd", "kev", "epss")
STATUSES = ("ok", "stale", "partial", "failed")
REQUIRED = ("schema_version", "sample", "generated", "total", "counts", "by_day", "kev_in_window",
            "kev_recent", "items", "source_status", "retention", "meta")
MIN_TOTAL = 50      # a 14-day window always holds far more than this; fewer means a bad pull
MIN_KEV = 500       # the real KEV catalog holds well over 1,000 entries
MAX_ERRORS = 50

def valid_date(x):
    """A real calendar date in YYYY-MM-DD form (rejects 2026-02-30 and similar)."""
    if not (isinstance(x, str) and DATE_RE.match(x)):
        return False
    try:
        datetime.strptime(x, "%Y-%m-%d")
        return True
    except ValueError:
        return False

def _num(x, lo, hi):
    return isinstance(x, (int, float)) and not isinstance(x, bool) and lo <= x <= hi

def _int(x):
    return isinstance(x, int) and not isinstance(x, bool) and x >= 0

def validate(s, prev=None, min_total=MIN_TOTAL, now=None):
    """Return a list of problems; an empty list means the snapshot may be published."""
    if not isinstance(s, dict):
        return ["snapshot is not a JSON object"]
    e = [f"missing key: {k}" for k in REQUIRED if k not in s]
    if e:
        return e
    now = now or datetime.now(timezone.utc)
    if s["schema_version"] != 2:
        e.append("schema_version must be 2")
    if s["sample"] is not False:
        e.append("a live snapshot must have sample=false")
    try:
        gen = datetime.strptime(s["generated"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        if gen > now + timedelta(days=1):
            e.append("generated is in the future")
    except (TypeError, ValueError):
        e.append("generated must look like 2026-11-14T06:00:00Z")
    if not isinstance(s["items"], list):
        return e + ["items is not a list"]
    seen, recount, by_pub = set(), {k: 0 for k in SEVS}, {}
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
        if i.get("severity") in SEVS:
            recount[i["severity"]] += 1
            if valid_date(i.get("published")):
                by_pub.setdefault(i["published"], {k: 0 for k in SEVS})[i["severity"]] += 1
        else:
            e.append(f"{cid}: bad severity {i.get('severity')!r}")
        if i.get("score") is not None and not _num(i["score"], 0, 10):
            e.append(f"{cid}: score out of range")
        if i.get("epss") is not None and not _num(i["epss"], 0, 1):
            e.append(f"{cid}: epss out of range")
        for f in ("published", "modified"):
            if not valid_date(i.get(f)):
                e.append(f"{cid}: bad {f} date")
        for f in ("kev_added", "kev_due", "epss_date"):
            if i.get(f) and not valid_date(i[f]):
                e.append(f"{cid}: bad {f}")
        if not isinstance(i.get("kev"), bool):
            e.append(f"{cid}: kev must be true or false")
        if not isinstance(i.get("desc"), str):
            e.append(f"{cid}: desc must be text")
    c = s["counts"]
    if not (isinstance(c, dict) and all(_int(c.get(k)) for k in SEVS)):
        e.append("counts must hold an integer for every severity")
    elif c != recount and len(e) < MAX_ERRORS:
        e.append("counts do not match the saved records")
    if s["total"] != len(s["items"]):
        e.append(f"total ({s['total']}) must equal the number of saved records ({len(s['items'])})")
    elif s["total"] < min_total:
        e.append(f"only {s['total']} CVEs retrieved (minimum {min_total}); refusing to publish")
    if not isinstance(s["by_day"], dict):
        e.append("by_day must map dates to counts")
    else:
        for d, b in s["by_day"].items():
            if not valid_date(d) or not (isinstance(b, dict) and all(_int(b.get(k)) for k in SEVS)):
                e.append(f"by_day entry {d!r} is malformed")
            elif b != by_pub.get(d, {k: 0 for k in SEVS}):
                e.append(f"by_day {d} does not match the saved records")
    if not isinstance(s["kev_recent"], list) or not all(
            isinstance(k, dict) and ID_RE.match(str(k.get("id", ""))) for k in s["kev_recent"]):
        e.append("kev_recent must be a list of KEV entries")
    ss = s["source_status"]
    if not isinstance(ss, dict):
        e.append("source_status must be an object")
    else:
        for k in SOURCES:
            if not (isinstance(ss.get(k), dict) and ss[k].get("status") in STATUSES):
                e.append(f"source_status.{k} is missing or has an unknown status")
        if isinstance(ss.get("nvd"), dict) and ss["nvd"].get("status") != "ok":
            e.append("NVD status must be ok to publish")
    if not (isinstance(s["meta"], dict) and _int(s["meta"].get("omitted"))):
        e.append("meta.omitted must be a whole number")
    # Shrink guard only applies when the retention rule is unchanged, so a deliberate rule change can publish.
    if prev and prev.get("retention") == s.get("retention") and _int(prev.get("total")) and prev["total"] >= 100 \
            and _int(s["total"]) and s["total"] < prev["total"] * 0.4:
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
        if not valid_date(x.get("added")):
            e.append(f"KEV {cid}: bad added date")
        if x.get("due") and not valid_date(x["due"]):
            e.append(f"KEV {cid}: bad due date")
    return e

if __name__ == "__main__":
    bad = False
    for path in sys.argv[1:] or ["data/cve-snapshot.json"]:
        try:
            with open(path, encoding="utf-8") as f:
                obj = json.load(f)
        except Exception as ex:
            print(f"{path}: not valid JSON ({ex})"); bad = True; continue
        errs = validate_kev(obj) if "entries" in obj else validate(obj)
        print(f"{path}: {'OK' if not errs else 'FAILED'}")
        for x in errs: print("  -", x)
        bad = bad or bool(errs)
    sys.exit(1 if bad else 0)
