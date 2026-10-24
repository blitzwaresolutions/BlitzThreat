# BlitzThreat EEM
**Environmental Event Management.** 

BlitzThreat EEM (BTEEM) is the security monitoring product of the BlitzWare Solutions LLC suite. This repository contains the **demo launcher**: a single-file HTML/JavaScript app that starts with a threat map portal and is the foundation for incident response, vulnerability tracking, telemetry and, eventually, a SIEM.

- Product page: https://blitzwaresolutions.github.io/bws/blitzthreat.html
- Solutions page: https://blitzwaresolutions.github.io/bws/solutions.html

> Status: early demo. Demo mode is a UI preview and provides **no security**. See [Security](#security).

## What the demo does

- Log-on splash screen shown before the landing page
- Landing page for selecting one of the **top 5 public threat maps**, opened in a new tab:
  - Fortinet Threat Map
  - Bitdefender Threat Map
  - Kaspersky Cyber Map
  - Check Point Live Cyber Threat Map
  - Radware Live Threat Map
- Swipe (touch) and arrow-key navigation, Enter to open
- Optional SSO via OpenID Connect (Authorization Code + PKCE)
- Placeholders for upcoming modules: Incident Response, CVE/CVSS, Telemetry, App Logs, BlitzGate

Map data comes from public OSINT sources. Map URLs are controlled by their vendors and may change.

## Run locally

No build step. Open `index.html` in a browser, or serve it:

```bash
python3 -m http.server 8080
# then visit http://localhost:8080
```

## Deploy on GitHub Pages

1. Push this folder to a repository, for example `blitzwaresolutions/blitzthreat`.
2. In **Settings > Pages**, set the source to the `main` branch, root folder.
3. The demo is served over HTTPS at `https://blitzwaresolutions.github.io/blitzthreat/`.

Then point the "Launch demo" button in `blitzthreat.html` (in the `bws` repository) at that URL.

## Security

**TLS.** Serve only over HTTPS. GitHub Pages provides this. For self-hosting use Caddy, Nginx or Cloudflare with automatic certificates, and send `Strict-Transport-Security`, `X-Content-Type-Options`, `Referrer-Policy` and `X-Frame-Options` as real HTTP headers. The app disables sign-in on plain HTTP.

**SSO.** Edit the `CFG` block near the top of the script in `index.html`:

| Field | Value |
|---|---|
| `authorizeUrl` | IdP authorization endpoint |
| `tokenUrl` | IdP token endpoint |
| `clientId` | Public client ID registered for this app (never a client secret) |
| `redirectUri` | Defaults to the page URL; register it exactly with the IdP |

Works with OIDC providers such as Entra ID, Okta, Keycloak and Auth0. With `CFG` empty, the app runs in demo mode.

**Important limitation.** A static page cannot enforce authentication, because the client code can be changed by anyone. Production use needs a backend that validates ID tokens (signature, issuer, audience, nonce), issues an HttpOnly session cookie, and serves protected content only to authenticated users.

## CVE dashboard and live data pipeline

`dashboard.html` is a static page that reads snapshot files built by a scheduled GitHub Action. No key or backend is ever exposed to visitors.

```
NVD API 2.0 + CISA KEV catalog + FIRST EPSS
  -> scripts/fetch_cve.py (retrieve, normalize, merge, deduplicate)
  -> scripts/validate_snapshot.py (schema and integrity checks)
  -> atomic replace of data/cve-snapshot.json (only if validation passes)
  -> dashboard.html
```

**Files in `data/`:** `cve-snapshot.json` (tracked CVEs, severity counts, per-day counts, per-source status), `kev-catalog.json` (the complete CISA KEV catalog), `ingest-status.json` (result of the latest attempt, so the dashboard can show failed refreshes).

**Schedule:** daily at 06:00 UTC and on demand (Actions > Update CVE snapshot > Run workflow; tick "full_refresh" for a 30-day reconcile). Sunday runs reconcile automatically. Each run re-pulls everything modified in the lookback window (14 days, widened automatically after an outage, 119 days at most), so a missed run leaves no gap. Records are kept if published in the last 14 days or modified in the last 7.

**Failure behavior**
- NVD failure, an empty result, or any validation failure: the run fails, the last good snapshot is untouched, and `ingest-status.json` records the failure. The dashboard shows a warning.
- KEV failure: the previous catalog is reused and marked "stale". EPSS failure: earlier scores are kept and the source is marked "partial" or "failed". Neither erases valid NVD data.
- Files are written to a temporary file, re-read, and only then moved into place. Unchanged data is not committed again.
- The workflow runs the offline tests first: `python -m unittest discover -s scripts -p "test_*.py"`.

**Setup**
1. Optional: request a free NVD API key and save it as the repository secret `NVD_API_KEY`. It is used only inside the Action. Without it the script runs more slowly because of NVD's rate limit.
2. Run the workflow once. Until the first successful run the dashboard keeps showing the sample data and its "SAMPLE DATA" notice.
3. Before pushing a change, tag the current version so you can roll back (`git tag BTEEM_BASE2_<previous>`).

**On-demand CVE lookup.** The dashboard asks NVD (CVE record) and FIRST (EPSS) directly from the browser, and checks KEV against `data/kev-catalog.json`. Results show the source and retrieval time. If the live request fails, a cached snapshot record is shown with a clear "FROM SNAPSHOT" label, never as fresh data. Browser-direct access depends on those services allowing cross-origin requests and on their rate limits, so test it on the deployed site. If NVD blocks browser requests, the options are a small free-tier proxy (for example a Cloudflare Worker that holds the NVD key and rate-limits requests) or dropping lookup of CVEs that are not in the snapshot. Nothing secret is ever placed in the page.

**Run locally**
```bash
export NVD_API_KEY=...            # optional
python3 scripts/fetch_cve.py
python3 -m http.server 8080 --bind 127.0.0.1
```

## Roadmap

1. **Backend:** OIDC callback, token validation, sessions, role-based access.
2. **CVE/CVSS page:** NVD API 2.0, CISA Known Exploited Vulnerabilities, EPSS scores.
3. **Incident Response portal:** incident records, status workflow aligned to NIST SP 800-61 (detect, triage, contain, eradicate, recover, review), timeline and evidence log.
4. **Telemetry and logs:** a common event schema (OCSF or ECS), collectors for connected apps, dashboards.
5. **LLM and agents:** read-only tools first (CVE lookup, incident summaries) behind an allowlist, with every call logged.
6. **SIEM:** correlation rules, alerting, retention and search built on the event schema.

## BlitzGate and BlitzRAG

**BlitzGate** is a planned gateway for the **BlitzRAG** data pipeline. It checks data against governance policy and detects PHI, PII and ePHI before it moves through the pipeline. Design intent: fail closed, redact or block on a match, and write an audit record for every decision. ePHI handling will follow HIPAA Security Rule controls (audit logging, access control, encryption in transit and at rest).

## Repository layout

```
bteem.html     Demo app (launcher, splash, SSO)
dashboard.html CVE/CVSS dashboard (reads data/cve-snapshot.json)
scripts/       fetch_cve.py, validate_snapshot.py, test_ingest.py
data/          cve-snapshot.json (generated)
.github/       Scheduled workflow that refreshes the snapshot
README.md      This file
LICENSE        All rights reserved
.gitignore     Excludes secrets, logs, dependencies, build output
.nojekyll      Serve files as-is on GitHub Pages
```

## License

Copyright (c) 
  <div>&copy; 2026 <a href="https://BlitzWareSolutions.github.io/bws">BlitzWare Solutions LLC</a> All Rights Reserved</div> See `LICENSE`.
