# ThreatSumm4ry CI/CD and Deployment

This repo is deployed as two surfaces:

- Cloudflare Pages: static frontend from `dist/` plus Pages Functions from
  `functions/`.
- VPS: Node backend from `server/`, with runtime state and secrets kept outside
  releases.

## Pipelines

### CI

`.github/workflows/ci.yml` runs on every push and pull request:

- frontend: `npm ci`, lint, typecheck and Vite build
- backend: `npm --prefix server ci` and Node syntax checks
- hunt-service: Python source compile check

### Security Scans

`.github/workflows/vulnerability-scan.yml` runs on `main`, PRs and weekly:

- `npm audit` for root and `server/`
- OSV dependency scan
- Gitleaks secret detection
- Trivy filesystem/config scan with SARIF upload

CodeQL runs separately in `.github/workflows/codeql.yml`.

### Cloudflare Pages

`.github/workflows/deploy-pages.yml` runs after CI succeeds on `main`, or
manually with `workflow_dispatch`.

Required GitHub Actions variables:

```txt
CLOUDFLARE_PAGES_PROJECT
```

Required GitHub Actions secrets:

```txt
CLOUDFLARE_ACCOUNT_ID
CLOUDFLARE_API_TOKEN
```

Required Cloudflare Pages environment variable:

```txt
API_ORIGIN=https://origin.example.com
```

`API_ORIGIN` is used by `functions/api/[[path]].js` to proxy `/api/*` to the
VPS without exposing API keys to the browser.

### VPS

`.github/workflows/deploy-vps.yml` runs after CI succeeds on `main`, or manually
with `workflow_dispatch`.

Required GitHub Actions variables:

```txt
VPS_HOST=example.com
VPS_USER=deploy
VPS_PORT=22
VPS_APP_DIR=/opt/threatsumm4ry
VPS_SERVICE=threatsumm4ry.service
VPS_HEALTHCHECK_URL=https://origin.example.com/api/vendors/status
```

Required GitHub Actions secrets:

```txt
VPS_SSH_PRIVATE_KEY
VPS_KNOWN_HOSTS
```

Generate `VPS_KNOWN_HOSTS` from a trusted machine:

```bash
ssh-keyscan -p 22 example.com
```

The deploy workflow creates release directories like:

```txt
/opt/threatsumm4ry/releases/<git-sha>
/opt/threatsumm4ry/current -> /opt/threatsumm4ry/releases/<git-sha>
/opt/threatsumm4ry/shared/.env
```

It syncs `dist/`, `server/`, `src/config/`, root package metadata and nginx/Docker
support files. It never syncs `.env`, `node_modules` or backend runtime stores.

## First VPS Setup

Create a deploy user and app directory:

```bash
sudo useradd --create-home --shell /bin/bash deploy
sudo mkdir -p /opt/threatsumm4ry/shared /opt/threatsumm4ry/releases
sudo chown -R deploy:deploy /opt/threatsumm4ry
```

Create `/opt/threatsumm4ry/shared/.env` from
[server/.env.example](./server/.env.example):

```bash
sudo -u deploy cp /path/to/server/.env.example /opt/threatsumm4ry/shared/.env
sudo chmod 600 /opt/threatsumm4ry/shared/.env
```

Install Node.js 20 on the VPS and create a systemd service:

```ini
[Unit]
Description=ThreatSumm4ry backend
After=network.target

[Service]
Type=simple
User=deploy
WorkingDirectory=/opt/threatsumm4ry/current/server
Environment=NODE_ENV=production
ExecStart=/usr/bin/node index.js
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable it:

```bash
sudo systemctl daemon-reload
sudo systemctl enable threatsumm4ry.service
```

Allow the deploy user to restart only this service:

```sudoers
deploy ALL=(root) NOPASSWD: /usr/bin/systemctl restart threatsumm4ry.service, /usr/bin/systemctl --no-pager --lines=30 status threatsumm4ry.service
```

## Branch and Environment Policy

- Pull requests run CI and security checks but cannot access deployment secrets.
- Pushes to `main` deploy only after CI success.
- Use GitHub Environments (`cloudflare-pages`, `vps-production`) with required
  reviewers if you want manual approval before production publishing.
- Rotate `VPS_SSH_PRIVATE_KEY`, `CLOUDFLARE_API_TOKEN`, `SESSION_SECRET` and
  `SECRETS_ENCRYPTION_KEY` if a secret is ever exposed.
