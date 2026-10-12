# ThreatSumm4ry

Open source CTI platform for collecting security feeds, curating publications
and producing intelligence reports. Licensed under [AGPL-3.0-only](./LICENSE).

The product centers on an analyst workflow: **news and IOCs → saved publications → reports**.
CVE tracking, actor context, ransomware data and indicator lookup support that
research. The hosted instance currently restricts news, saved publications and reports
to authorized accounts; running your own instance requires configuring its
integrations and access settings.

The ETL preserves source evidence, caches collection results across restarts and
groups coverage under stable story IDs. Current correlation uses deterministic
heuristics; semantic event clustering and a persistent threat graph are roadmap
items. See [ETL architecture and operations](./docs/product/etl-v2.md),
[product direction](./docs/product/direction.md) and the
[CTINexus evaluation](./docs/product/ctinexus-evaluation.md).

The indicator analyzer accepts public IPv4/IPv6 addresses, domains, HTTP/HTTPS
URLs, and MD5, SHA-1, or SHA-256 hashes.

## Stack

- React 18 + Vite + TypeScript
- Tailwind CSS + shadcn/ui
- Express backend proxy in `server/` (aggregates the upstream intel APIs and
  keeps their keys server-side)
- Cloudflare Pages Functions in `functions/`

## Data sources

The backend fans out to public/authenticated CTI feeds and normalizes them, so
the browser never talks to a third party directly:

- **CVEs** — NIST NVD 2.0 (`services.nvd.nist.gov`, key raises the rate limit),
  with CIRCL (`cve.circl.lu`) as fallback; CISA KEV for known-exploited.
- **Ransomware** — `ransomware.live` v1 (keyless) for recent claimed victims.
- **IOC/malware** — abuse.ch (ThreatFox, URLhaus, MalwareBazaar), AlienVault
  OTX, AbuseIPDB, VirusTotal, Shodan, OpenPhish, PhishStats, PhishTank, and abuse.ch.
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
push main ──▶ CI (lint · typecheck · build · node --check)
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
Shodan, AbuseIPDB, abuse.ch, etc.

Users can add personal Shodan and urlscan.io keys in **Settings → API keys**.
Keys are encrypted with `SECRETS_ENCRYPTION_KEY` and stored per account in
`server/.users.json`; API responses expose only whether a key is configured.
Personal keys take precedence over the platform keys. urlscan.io BYOK applies
to manual brand searches and scheduled monitoring of the account's organization
profiles. It searches existing scans. Exhausting one credential's quota does
not stop profiles using other credentials.
