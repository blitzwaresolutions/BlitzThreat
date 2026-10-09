# BlitzThreat EEM 

**EEM = Environmental Event Management.** BlitzThreat EEM (BTEEM) is the security monitoring product of the BlitzWare Solutions LLC suite. This repository contains the **demo launcher**: a single-file HTML/JavaScript app that starts with a threat map portal and is the foundation for incident response, vulnerability tracking, telemetry and, eventually, a SIEM.

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

1. Push this folder to a repository, for example `blitzwaresolutions/blitzthreat-eem`.
2. In **Settings > Pages**, set the source to the `main` branch, root folder.
3. The demo is served over HTTPS at `https://blitzwaresolutions.github.io/blitzthreat-eem/`.

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

## CVE dashboard and data pipeline

`dashboard.html` shows live public CVE data without putting any key or backend in front of visitors.

1. A scheduled GitHub Action (`.github/workflows/update-cve.yml`, daily) runs `scripts/fetch_cve.py`.
2. The script pulls recent CVEs from the **NIST NVD API 2.0**, flags entries in the **CISA KEV** catalog, adds **FIRST EPSS** exploit-likelihood scores, and writes `data/cve-snapshot.json`.
3. The dashboard reads that same-origin JSON file. It never calls a third-party API from the browser.

**Setup**
- Optional but recommended: request a free NVD API key and save it as the repository secret `NVD_API_KEY` (Settings > Secrets and variables > Actions). The key is used only inside the Action.
- Run the workflow once from the Actions tab (Run workflow) to create the first snapshot.

**Run locally (for example on Kali)**
```bash
export NVD_API_KEY=...            # optional
python3 scripts/fetch_cve.py      # writes data/cve-snapshot.json
python3 -m http.server 8080 --bind 127.0.0.1
```
Open `http://127.0.0.1:8080`. Bind to `127.0.0.1` only. Run as a normal user, not root.

Snapshot data is only as fresh as the last run. Dashboard text is treated as untrusted and is inserted with `textContent`.

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
index.html     Demo app (launcher, splash, SSO)
dashboard.html CVE/CVSS dashboard (reads data/cve-snapshot.json)
scripts/       fetch_cve.py snapshot builder (stdlib Python)
data/          cve-snapshot.json (generated)
.github/       Scheduled workflow that refreshes the snapshot
README.md      This file
LICENSE        All rights reserved
.gitignore     Excludes secrets, logs, dependencies, build output
.nojekyll      Serve files as-is on GitHub Pages
```

## License

Copyright (c) 2026 BlitzWare Solutions LLC. All rights reserved. See `LICENSE`.

