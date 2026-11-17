# BTEEM_BASE2_111626a
"""Offline tests for the BTEEM ingestion pipeline. All sources are mocked; no network is used."""
import contextlib, copy, io, json, os, sys, tempfile, unittest, urllib.parse
from datetime import datetime, timedelta, timezone
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fetch_cve as fc
from validate_snapshot import validate, validate_kev

NOW = datetime.now(timezone.utc)

def nvd_rec(cid, pub_days_ago, score):
    pub = (NOW - timedelta(days=pub_days_ago)).strftime("%Y-%m-%dT10:00:00.000")
    mod = NOW.strftime("%Y-%m-%dT09:00:00.000")
    sev = "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"
    return {"cve": {"id": cid, "published": pub, "lastModified": mod, "vulnStatus": "Analyzed",
                    "descriptions": [{"lang": "en", "value": f"Test record {cid}"}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": score, "baseSeverity": sev,
                                                                "vectorString": "CVSS:3.1/AV:N"}}]}}}

def base_rec(n):
    return nvd_rec(f"CVE-2026-{1000 + n}", n % 5, float(n % 10) or 1.0)

def expected_epss(cid):
    return (int(cid[-4:]) % 100) / 100

class Fake:
    def __init__(self, n=80):
        self.n, self.nvd_fail, self.kev_fail, self.epss_fail = n, False, False, False
        self.page_size, self.cut_at, self.extras = 5000, None, False
    def records(self):
        recs = [base_rec(i) for i in range(self.n)]
        if self.n:
            recs.append(base_rec(0))                                          # duplicate record
            rej = base_rec(900); rej["cve"]["vulnStatus"] = "Rejected"; recs.append(rej)
        if self.extras:                       # old CVEs (published 100 days ago) modified today
            recs += [nvd_rec("CVE-2020-5001", 100, 2.0), nvd_rec("CVE-2020-5002", 100, 8.0), nvd_rec("CVE-2020-5003", 100, 2.0)]
        return recs
    def __call__(self, url, headers=None, tries=4):
        if url.startswith(fc.NVD):
            if self.nvd_fail: raise OSError("simulated NVD outage")
            recs = self.records()
            start = int(urllib.parse.parse_qs(urllib.parse.urlparse(url).query)["startIndex"][0])
            chunk = [] if self.cut_at is not None and start >= self.cut_at else recs[start:start + self.page_size]
            return {"timestamp": "2026-10-22T06:00:00.000", "totalResults": len(recs), "vulnerabilities": chunk}
        if url.startswith(fc.KEV):
            if self.kev_fail: raise OSError("simulated KEV outage")
            row = lambda cid, added, due, r: {"cveID": cid, "vendorProject": "V", "product": "P", "vulnerabilityName": "N",
                                              "dateAdded": added, "dueDate": due, "knownRansomwareCampaignUse": r}
            rows = [row(f"CVE-2015-{1000 + k}", "2022-03-03", "2022-03-24", "Unknown") for k in range(520)]
            rows += [row("CVE-2026-1001", NOW.strftime("%Y-%m-%d"), "2026-11-12", "Known"),
                     row("CVE-2026-1003", "2021-11-03", "2021-11-17", "Unknown")]
            if self.extras: rows.append(row("CVE-2020-5003", "2021-12-01", "2021-12-15", "Unknown"))
            return {"catalogVersion": "2026.10.21", "dateReleased": "2026-10-21T00:00:00.000Z", "vulnerabilities": rows}
        if url.startswith(fc.EPSS):
            if self.epss_fail: raise OSError("simulated EPSS outage")
            ids = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)["cve"][0].split(",")
            return {"data": [{"cve": i, "epss": f"{expected_epss(i):.5f}", "percentile": "0.5", "date": "2026-10-21"} for i in ids]}
        raise AssertionError("unexpected URL " + url)

class T(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory(); self.dir = self._t.name; self.logs = ""
    def tearDown(self): self._t.cleanup()
    def p(self, f): return os.path.join(self.dir, f)
    def read(self, f):
        with open(self.p(f), "rb") as fh:
            return fh.read()
    def js(self, f): return json.loads(self.read(f))
    def run_ingest(self, fake):
        out = io.StringIO()
        with mock.patch.object(fc, "get", fake), mock.patch.object(fc.time, "sleep", lambda s: None), \
             mock.patch.dict(os.environ, {"BTEEM_DATA_DIR": self.dir, "NVD_API_KEY": "SECRETKEY123"}), \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            rc = fc.main()
        self.logs += out.getvalue()
        return rc

    def test_happy_path(self):
        self.assertEqual(self.run_ingest(Fake()), 0)
        s = self.js("cve-snapshot.json")
        self.assertEqual(validate(s), [])
        ids = [i["id"] for i in s["items"]]
        self.assertEqual(len(ids), len(set(ids)))                          # duplicates removed
        self.assertEqual(s["total"], 80); self.assertEqual(len(ids), 80)   # rejected record dropped, total == saved
        self.assertEqual(sum(s["counts"].values()), 80)                    # charts and search cover the same records
        for i in s["items"]:
            self.assertAlmostEqual(i["epss"], expected_epss(i["id"]))       # EPSS matched to the right CVE
        by = {i["id"]: i for i in s["items"]}
        self.assertTrue(by["CVE-2026-1001"]["kev"]); self.assertTrue(by["CVE-2026-1001"]["kev_ransomware"])
        self.assertEqual(by["CVE-2026-1003"]["kev_added"], "2021-11-03")   # older KEV entry still flagged
        self.assertEqual([k["id"] for k in s["kev_recent"]], ["CVE-2026-1001"])
        self.assertEqual(self.js("ingest-status.json")["result"], "ok")
        self.assertEqual(validate_kev(self.js("kev-catalog.json")), [])
        self.assertEqual(len(self.js("kev-catalog.json")["entries"]), 522)  # complete catalog kept

    def test_multi_page_pull_is_complete(self):
        f = Fake(); f.page_size = 30
        self.assertEqual(self.run_ingest(f), 0)
        self.assertEqual(self.js("cve-snapshot.json")["total"], 80)

    def test_incomplete_pagination_is_rejected(self):
        self.run_ingest(Fake()); before = self.read("cve-snapshot.json")
        f = Fake(); f.page_size = 30; f.cut_at = 30                          # page 2 comes back empty
        self.assertEqual(self.run_ingest(f), 1)
        self.assertEqual(self.read("cve-snapshot.json"), before)
        self.assertIn("incomplete", self.js("ingest-status.json")["message"])

    def test_retention_rule(self):
        f = Fake(); f.extras = True
        self.assertEqual(self.run_ingest(f), 0)
        ids = {i["id"] for i in self.js("cve-snapshot.json")["items"]}
        self.assertNotIn("CVE-2020-5001", ids)        # old, low severity, not exploited: dropped
        self.assertIn("CVE-2020-5002", ids)           # old but HIGH and recently modified: kept
        self.assertIn("CVE-2020-5003", ids)           # old but known exploited: kept

    def test_safety_limit_keeps_counts_consistent(self):
        with mock.patch.object(fc, "MAX_ITEMS", 60):
            self.assertEqual(self.run_ingest(Fake()), 0)
        s = self.js("cve-snapshot.json")
        self.assertEqual((len(s["items"]), s["total"], sum(s["counts"].values()), s["meta"]["omitted"]), (60, 60, 60, 20))
        self.assertEqual(validate(s), [])

    def test_nvd_failure_keeps_snapshot(self):
        self.run_ingest(Fake()); before = self.read("cve-snapshot.json")
        f = Fake(); f.nvd_fail = True
        self.assertEqual(self.run_ingest(f), 1)
        self.assertEqual(self.read("cve-snapshot.json"), before)
        st = self.js("ingest-status.json")
        self.assertEqual(st["result"], "failed"); self.assertIn("NVD", st["message"])

    def test_empty_result_cannot_replace_or_create(self):
        self.run_ingest(Fake()); before = self.read("cve-snapshot.json")
        self.assertEqual(self.run_ingest(Fake(n=0)), 1)
        self.assertEqual(self.read("cve-snapshot.json"), before)
        self.dir = tempfile.mkdtemp()                                       # first run with no baseline
        self.assertEqual(self.run_ingest(Fake(n=0)), 1)
        self.assertFalse(os.path.exists(self.p("cve-snapshot.json")))

    def test_kev_failure_reuses_catalog(self):
        self.run_ingest(Fake()); cat = self.read("kev-catalog.json")
        f = Fake(); f.kev_fail = True
        self.assertEqual(self.run_ingest(f), 0)
        s = self.js("cve-snapshot.json")
        self.assertEqual(s["source_status"]["kev"]["status"], "stale")
        self.assertEqual(self.read("kev-catalog.json"), cat)
        self.assertTrue({i["id"]: i for i in s["items"]}["CVE-2026-1001"]["kev"])
        self.assertEqual(self.js("ingest-status.json")["result"], "partial")

    def test_epss_failure_keeps_earlier_scores(self):
        self.run_ingest(Fake())
        f = Fake(); f.epss_fail = True
        self.assertEqual(self.run_ingest(f), 0)
        s = self.js("cve-snapshot.json")
        self.assertEqual(s["source_status"]["epss"]["status"], "failed")
        for i in s["items"]:
            self.assertAlmostEqual(i["epss"], expected_epss(i["id"]))

    def test_no_rewrite_when_unchanged(self):
        self.run_ingest(Fake()); a, b = self.read("cve-snapshot.json"), self.read("ingest-status.json")
        self.assertEqual(self.run_ingest(Fake()), 0)
        self.assertEqual(a, self.read("cve-snapshot.json")); self.assertEqual(b, self.read("ingest-status.json"))

    def test_status_timestamps_follow_the_snapshot(self):
        self.run_ingest(Fake())
        old = (NOW - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
        for name in ("cve-snapshot.json", "ingest-status.json"):            # age the published files by 3 days
            txt = self.read(name).decode()
            gen = self.js("cve-snapshot.json")["generated"]
            with open(self.p(name), "w", encoding="utf-8") as fh: fh.write(txt.replace(gen, old))
        self.assertEqual(self.run_ingest(Fake()), 0)
        snap, st = self.js("cve-snapshot.json"), self.js("ingest-status.json")
        self.assertNotEqual(snap["generated"], old)
        self.assertEqual(st["last_success"], snap["generated"])             # status moved with the snapshot

    def test_secret_never_logged_or_written(self):
        self.run_ingest(Fake()); f = Fake(); f.nvd_fail = True; self.run_ingest(f)
        self.assertNotIn("SECRETKEY123", self.logs)
        for name in os.listdir(self.dir): self.assertNotIn(b"SECRETKEY123", self.read(name))

    def test_validator_rejects_bad_data(self):
        self.run_ingest(Fake()); good = self.js("cve-snapshot.json")
        def bad(mut):
            s = copy.deepcopy(good); mut(s); return validate(s)
        self.assertTrue(bad(lambda s: s["items"].append(dict(s["items"][0]))))               # duplicate
        self.assertTrue(bad(lambda s: s["items"][0].update(id="CVE-26-1")))                  # bad id
        self.assertTrue(bad(lambda s: s["items"][0].update(severity="SEVERE")))
        self.assertTrue(bad(lambda s: s["items"][0].update(score=11)))
        self.assertTrue(bad(lambda s: s["items"][0].update(epss=2)))
        self.assertTrue(bad(lambda s: s["items"][0].update(published="2026-02-30")))         # impossible date
        self.assertTrue(bad(lambda s: s["items"][0].update(kev_due="2026-13-01")))
        self.assertTrue(bad(lambda s: s.update(items=[], total=0)))                          # empty
        self.assertTrue(bad(lambda s: s.pop("counts")))                                      # missing key
        self.assertTrue(bad(lambda s: s.update(sample=True)))
        self.assertTrue(bad(lambda s: s["counts"].update(LOW=s["counts"]["LOW"] + 1)))       # counts vs records
        self.assertTrue(bad(lambda s: s.update(total=s["total"] + 1)))                       # total vs records
        self.assertTrue(bad(lambda s: s["by_day"].update({next(iter(s["by_day"])): {k: 99 for k in s["counts"]}})))
        self.assertTrue(bad(lambda s: s["source_status"].pop("epss")))                       # missing source status
        self.assertTrue(bad(lambda s: s["source_status"]["nvd"].update(status="failed")))
        self.assertTrue(bad(lambda s: s.update(generated="2099-01-01T00:00:00Z")))           # future timestamp
        self.assertTrue(bad(lambda s: s.update(generated="yesterday")))
        self.assertTrue(validate("not an object"))
        self.assertTrue(validate_kev({"entries": []}))
        s = copy.deepcopy(good)                                                             # shrink guard
        self.assertTrue(any("fell" in e for e in validate(s, prev={"total": 500, "retention": s["retention"]}, min_total=10)))
        self.assertEqual(validate(s, prev={"total": 500, "retention": {"modified_days": 7}}), [])   # rule changed: allowed

if __name__ == "__main__":
    unittest.main()
