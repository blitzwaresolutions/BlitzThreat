# BlitzThreat EEM (BTEEM)

**EEM = Environmental Event Management.**

BlitzThreat EEM is the security monitoring product of the [BlitzWare Solutions LLC](https://blitzwaresolutions.github.io/bws) suite. This repository contains the **demo launcher** and the **CVE Dashboard**: static HTML/JavaScript pages hosted on GitHub Pages, with vulnerability data refreshed automatically by a scheduled GitHub Action. It is the foundation for incident response, telemetry and, eventually, a SIEM.

- Demo: https://blitzwaresolutions.github.io/BlitzThreat/
- Product page: https://blitzwaresolutions.github.io/bws/blitzthreat.html
- Solutions page: https://blitzwaresolutions.github.io/bws/solutions.html

> Status: early demo with live CVE data. Demo sign-in mode is a UI preview and provides **no security**. See [Security](#security).

## What the demo does

- Log-on splash screen shown before the landing page
- Landing page for selecting one of the **top 5 public threat maps**, opened in a new tab:
  - Fortinet Threat Map
  - Bitdefender Threat Map
  - Kaspersky Cyber Map
  - Check Point Live Cyber Threat Map
  - Radware Live Threat Map
- Swipe (touch) and arrow-key navigation, Enter to open
- **CVE Dashboard** with live vulnerability data (see below)
- Optional SSO via OpenID Connect (Authorization Code + PKCE)
- Placeholders for upcoming modules: Incident Response, Telemetry, App Logs, BlitzGate

Map URLs are controlled by their vendors and may change.

## Live CVE data

The CVE Dashboard reads a static snapshot that a scheduled GitHub Action rebuilds every day. No API key or backend is ever exposed to visitors.

```
NVD API 2.0 + CISA KEV catalog + FIRST EPSS
  -> scripts/fetch_cve.py (retrieve, normalize, merge, deduplicate)
  -> scripts/validate_snapshot.py (schema and integrity checks)
  -> atomic replace of data/cve-snapshot.json (only if validation passes)
  -> dashboard.html
```

**Data files (`data/`)**
- `cve-snapshot.json`: tracked CVEs with CVSS score, severity, vector, publication and modified dates, KEV flag and due date, EPSS score and date, severity counts, per-day counts, and per-source status.
- `kev-catalog.json`: the complete CISA Known Exploited Vulnerabilities catalog.
- `ingest-status.json`: the result of the latest attempt.

**Schedule.** Daily at 06:00 UTC, and on demand from **Actions > Update CVE snapshot > Run workflow**. Sunday runs reconcile over a 30-day window. Each run re-pulls everything modified in the lookback window (14 days, widened automatically after an outage, 119 days at most), so a missed run leaves no gap. Records are kept if published in the last 14 days or modified in the last 7.

**Failure behavior**
- NVD failure, an empty result, or any validation failure: the run fails, the last good snapshot is left untouched, and `ingest-status.json` records the failure.
- KEV failure: the previous catalog is reused and marked "stale". EPSS failure: earlier scores are kept and the source is marked "partial" or "failed". Neither erases valid NVD data.
- Files are written to a temporary file, re-read, and only then moved into place. Unchanged data is not committed again.
- The workflow runs offline tests first: `python -m unittest discover -s scripts -p "test_*.py"`.

**Setup**
1. The workflow file must be at `.github/workflows/update-cve.yml` on the main branch. Files in the repository root are ignored by GitHub Actions.
2. Under Settings > Actions > General, "Allow all actions and reusable workflows" works. If you restrict actions, allow `actions/checkout` and `actions/setup-python`. The workflow requests its own `contents: write` permission.
3. Optional: request a free NVD API key and save it as the repository secret `NVD_API_KEY`. It is used only inside the Action. Without it the script runs more slowly because of NVD's rate limit.
4. Run the workflow once, then confirm the three files appear in `data/`.

**Run locally**
```bash
export NVD_API_KEY=...            # optional
python3 scripts/fetch_cve.py
python3 -m http.server 8080 --bind 127.0.0.1
# then visit http://127.0.0.1:8080/bteem.html
```

## Data sources and attribution

- **NIST National Vulnerability Database (NVD).** This product uses data from the NVD API but is not endorsed or certified by the NVD. https://nvd.nist.gov/developers/vulnerabilities
- **CISA Known Exploited Vulnerabilities (KEV) Catalog.** https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- **FIRST Exploit Prediction Scoring System (EPSS).** https://www.first.org/epss/

Snapshot data is only as fresh as the last successful run. Dashboard text comes from third parties and is treated as untrusted; it is inserted as plain text, never as HTML.

## Deploy on GitHub Pages

1. In **Settings > Pages**, set the source to the `main` branch, root folder.
2. The demo is served over HTTPS at `https://blitzwaresolutions.github.io/BlitzThreat/`.
3. The "Launch the demo" button in `blitzthreat.html` (in the `bws` repository) points to that URL.

## Security

**TLS.** Serve only over HTTPS. GitHub Pages provides this. For self-hosting use Caddy, Nginx or Cloudflare with automatic certificates, and send `Strict-Transport-Security`, `X-Content-Type-Options`, `Referrer-Policy` and `X-Frame-Options` as real HTTP headers. The app disables sign-in on plain HTTP.

**SSO.** Edit the `CFG` block near the top of the script in `bteem.html`:

| Field | Value |
|---|---|
| `authorizeUrl` | IdP authorization endpoint |
| `tokenUrl` | IdP token endpoint |
| `clientId` | Public client ID registered for this app (never a client secret) |
| `redirectUri` | Defaults to the page URL; register it exactly with the IdP |

Works with OIDC providers such as Entra ID, Okta, Keycloak and Auth0. With `CFG` empty, the app runs in demo mode.

**Important limitation.** A static page cannot enforce authentication, because the client code can be changed by anyone. Production use needs a backend that validates ID tokens (signature, issuer, audience, nonce), issues an HttpOnly session cookie, and serves protected content only to authenticated users.

**Secrets.** API keys live only in GitHub Actions secrets. Nothing secret belongs in the pages, the data files or the repository.

## Roadmap

Done: threat map launcher, splash and optional SSO, live CVE data pipeline (NVD, KEV, EPSS) with scheduled refresh and safe failure handling.

Next:
1. **CVE Dashboard improvements:** visible data freshness and failed-refresh warnings, KEV due dates and EPSS dates in the detail view, and on-demand lookup of a single CVE. Lookup depends on the source APIs allowing browser requests; if NVD blocks them, the options are a small free-tier proxy that holds the key, or limiting lookup to CVEs already in the snapshot.
2. **Backend:** OIDC callback, token validation, sessions, role-based access.
3. **Incident Response portal:** incident records, status workflow aligned to NIST SP 800-61 (detect, triage, contain, eradicate, recover, review), timeline and evidence log.
4. **Telemetry and logs:** a common event schema (OCSF or ECS), collectors for connected apps, dashboards.
5. **LLM and agents:** read-only tools first (CVE lookup, incident summaries) behind an allowlist, with every call logged.
6. **SIEM:** correlation rules, alerting, retention and search built on the event schema.

## BlitzGate and BlitzRAG

**BlitzGate** is a planned gateway for the **BlitzRAG** data pipeline. It checks data against governance policy and detects PHI, PII and ePHI before it moves through the pipeline. Design intent: fail closed, redact or block on a match, and write an audit record for every decision. ePHI handling will follow HIPAA Security Rule controls (audit logging, access control, encryption in transit and at rest).

## Repository layout

```
bteem.html          Launcher (splash, SSO, threat maps)
dashboard.html      CVE Dashboard (reads data/cve-snapshot.json)
scripts/            fetch_cve.py, validate_snapshot.py, test_ingest.py
data/               cve-snapshot.json, kev-catalog.json, ingest-status.json (generated)
.github/workflows/  update-cve.yml (scheduled refresh)
README.md           This file
LICENSE             All rights reserved
.gitignore          Excludes secrets, logs, dependencies, build output
.nojekyll           Serve files as-is on GitHub Pages
```

## License

© 2026 [BlitzWare Solutions LLC](https://blitzwaresolutions.github.io/bws) All Rights Reserved. See `LICENSE`
