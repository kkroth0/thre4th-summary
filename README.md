# ThreatSumm4ry

Threat intelligence workspace for IOC enrichment, CVE tracking, ransomware
tracking, advisory feeds, DNSBL checks, phishing analysis and guided threat
hunting.

## Stack

- React 18 + Vite + TypeScript
- Tailwind CSS + shadcn/ui
- Express backend proxy in `server/` (aggregates the upstream intel APIs and
  keeps their keys server-side)
- Cloudflare Pages Functions in `functions/`
- Optional FastAPI hunt microservice in `hunt-service/`

## Data sources

The backend fans out to public/authenticated CTI feeds and normalizes them, so
the browser never talks to a third party directly:

- **CVEs** — NIST NVD 2.0 (`services.nvd.nist.gov`, key raises the rate limit),
  with CIRCL (`cve.circl.lu`) as fallback; CISA KEV for known-exploited.
- **Ransomware** — `ransomware.live` v1 (keyless) for recent claimed victims.
- **IOC/malware** — abuse.ch (ThreatFox, URLhaus, MalwareBazaar), AlienVault
  OTX, AbuseIPDB, VirusTotal, Shodan, Censys, Pulsedive, and more.
- **Advisories** — MSRC, first.org, vendor RSS feeds.

Each integration is optional: missing a key just disables that one source.

## Local Development

```bash
npm ci
cp server/.env.example .env
npm run server
```

In another terminal:

```bash
npm run dev
```

Vite runs on `http://localhost:8080` and proxies `/api` to
`http://localhost:3001` by default.

## Quality Gates

```bash
npm run lint
npm run typecheck
npm run build
npm run ci
npm run ci:server
npm run ci:hunt
```

## Deployment Model

The frontend and the API run on **different hosts**, glued together by
Cloudflare:

- **Frontend → Cloudflare Pages** publishes `dist/` and `functions/`.
- **API → VPS** runs `server/index.js` under systemd; Cloudflare proxies
  `/api/*` to it (Pages exposes `API_ORIGIN` pointing at the VPS origin).

### CI/CD flow

Everything keys off a push to `main`:

```txt
push main ──▶ CI (lint · typecheck · build · node --check · py_compile)
                └─ on success ─┬─▶ deploy-pages.yml  → wrangler → Cloudflare Pages (frontend)
                               └─▶ deploy-vps.yml     → rsync + systemd restart (API)
```

- Both deploy jobs are gated on the CI workflow passing on `main`, and can also
  be run manually via **workflow_dispatch**.
- `deploy-vps.yml` ships a release to `$VPS_APP_DIR/releases/<sha>`, symlinks
  `current`, runs `npm ci --omit=dev`, restarts the service and health-checks.
- Pushing workflow changes over HTTPS needs a token with the `workflow` scope
  (`gh auth refresh -s workflow`); an SSH remote avoids that restriction.

See [DEPLOYMENT.md](./DEPLOYMENT.md) for the CI/CD secrets, VPS systemd layout
and first-deploy checklist.

## Runtime Secrets

Never commit `.env`. The backend reads the root `.env` file when started from
`server/` (dotenv loads `../.env`), and the GitHub Actions VPS deployment keeps
it on the server at:

```txt
$VPS_APP_DIR/shared/.env
```

Start from [server/.env.example](./server/.env.example). Notable optional keys:
`NVD_API_KEY` (CVE rate limit), plus the per-source keys for VirusTotal,
Shodan, Censys, AbuseIPDB, abuse.ch, etc.
