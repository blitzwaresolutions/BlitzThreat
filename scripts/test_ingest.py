"""Offline tests for the BTEEM ingestion pipeline. All sources are mocked; no network is used."""
import contextlib, copy, io, json, os, sys, tempfile, unittest, urllib.parse
from datetime import datetime, timedelta, timezone
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fetch_cve as fc
from validate_snapshot import validate, validate_kev

NOW = datetime.now(timezone.utc)

def nvd_rec(n):
    d = (NOW - timedelta(days=n % 5)).strftime("%Y-%m-%dT10:00:00.000")
    score = float(n % 10) or 1.0
    sev = "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"
    return {"cve": {"id": f"CVE-2026-{1000 + n}", "published": d, "lastModified": d, "vulnStatus": "Analyzed",
                    "descriptions": [{"lang": "en", "value": f"Test record {n}"}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": score, "baseSeverity": sev,
                                                                "vectorString": "CVSS:3.1/AV:N"}}]}}}

def expected_epss(cid):
    return (int(cid[-4:]) % 100) / 100

class Fake:
    def __init__(self, n=80):
        self.n, self.nvd_fail, self.kev_fail, self.epss_fail = n, False, False, False
    def __call__(self, url, headers=None, tries=4):
        if url.startswith(fc.NVD):
            if self.nvd_fail: raise OSError("simulated NVD outage")
            recs = [nvd_rec(i) for i in range(self.n)]
            if self.n:
                recs.append(nvd_rec(0))                                   # duplicate record
                rej = nvd_rec(900); rej["cve"]["vulnStatus"] = "Rejected"; recs.append(rej)
            return {"timestamp": "2026-10-22T06:00:00.000", "totalResults": len(recs), "vulnerabilities": recs}
        if url.startswith(fc.KEV):
            if self.kev_fail: raise OSError("simulated KEV outage")
            old = [{"cveID": f"CVE-2015-{1000 + k}", "vendorProject": "V", "product": "P", "vulnerabilityName": "N",
                    "dateAdded": "2022-03-03", "dueDate": "2022-03-24", "knownRansomwareCampaignUse": "Unknown"} for k in range(520)]
            hit = [{"cveID": "CVE-2026-1001", "vendorProject": "Acme", "product": "Widget", "vulnerabilityName": "Acme RCE",
                    "dateAdded": NOW.strftime("%Y-%m-%d"), "dueDate": "2026-11-12", "knownRansomwareCampaignUse": "Known"},
                   {"cveID": "CVE-2026-1003", "vendorProject": "Old", "product": "Thing", "vulnerabilityName": "Old bug",
                    "dateAdded": "2021-11-03", "dueDate": "2021-11-17", "knownRansomwareCampaignUse": "Unknown"}]
            return {"catalogVersion": "2026.10.21", "dateReleased": "2026-10-21T00:00:00.000Z", "vulnerabilities": old + hit}
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
        self.assertEqual(s["total"], 80)                                    # rejected record dropped
        for i in s["items"]:
            self.assertAlmostEqual(i["epss"], expected_epss(i["id"]))       # EPSS matched to the right CVE
        by = {i["id"]: i for i in s["items"]}
        self.assertTrue(by["CVE-2026-1001"]["kev"]); self.assertTrue(by["CVE-2026-1001"]["kev_ransomware"])
        self.assertEqual(by["CVE-2026-1003"]["kev_added"], "2021-11-03")   # older KEV entry still flagged
        self.assertTrue(by["CVE-2026-1003"]["kev"])
        self.assertEqual([k["id"] for k in s["kev_recent"]], ["CVE-2026-1001"])
        self.assertEqual(self.js("ingest-status.json")["result"], "ok")
        self.assertEqual(validate_kev(self.js("kev-catalog.json")), [])
        self.assertEqual(len(self.js("kev-catalog.json")["entries"]), 522)  # complete catalog kept

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
        self.assertTrue(bad(lambda s: s["items"][0].update(published="yesterday")))
        self.assertTrue(bad(lambda s: s.update(items=[], total=0)))                          # empty
        self.assertTrue(bad(lambda s: s.pop("counts")))                                      # missing key
        self.assertTrue(bad(lambda s: s.update(sample=True)))
        self.assertTrue(validate("not an object"))
        s = copy.deepcopy(good); s["total"] = 60; s["counts"] = {"CRITICAL": 60, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNSCORED": 0}
        self.assertTrue(any("fell" in e for e in validate(s, prev={"total": 200})))          # shrink guard
        self.assertTrue(validate_kev({"entries": []}))

if __name__ == "__main__":
    unittest.main()
