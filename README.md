# ThreatSumm4ry

Threat intelligence workspace for IOC enrichment, CVE tracking, advisory feeds,
DNSBL checks, phishing analysis and guided threat hunting.

## Stack

- React 18 + Vite + TypeScript
- Tailwind CSS + shadcn/ui
- Express backend proxy in `server/`
- Cloudflare Pages Functions in `functions/`
- Optional FastAPI hunt microservice in `hunt-service/`

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

- Cloudflare Pages publishes `dist/` and `functions/`.
- The VPS runs `server/index.js` behind Cloudflare Tunnel or another HTTPS
  reverse proxy.
- Cloudflare Pages should expose `API_ORIGIN`, pointing to the VPS origin.

See [DEPLOYMENT.md](./DEPLOYMENT.md) for the CI/CD secrets, VPS systemd layout
and first-deploy checklist.

## Runtime Secrets

Never commit `.env`. The backend reads the root `.env` file when started from
`server/`, and the GitHub Actions VPS deployment keeps it on the server at:

```txt
$VPS_APP_DIR/shared/.env
```

Start from [server/.env.example](./server/.env.example).
