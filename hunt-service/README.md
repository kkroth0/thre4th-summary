---
title: Thre4th Hunt Service
emoji: 🎯
colorFrom: blue
colorTo: indigo
sdk: docker
app_port: 7860
pinned: false
---

# ThreatSumm4ry — Hunt Service

Python microservice that turns a security-report URL into a validated **Threat
Hunting Pack**: scrape → Groq (Llama 3.3 70B) → Pydantic validation/retry → defanged
structured output (threat actor, MITRE TTPs, IOCs, hunting hypothesis, Sentinel
KQL + Sigma, CISO/SOC briefs).

It sits behind the Node backend, which proxies to it (`/api/newsletter/hunt-pack`)
and enforces the advisory allowlist. This service additionally requires the
`X-Hunt-Secret` header.

## Files
- `scraper.py` — Scrapling ingestion (lightweight fetch, stealth-browser fallback).
- `analyzer.py` — Groq call + Pydantic schema + validate-or-retry + defang.
- `main.py` — FastAPI app: `POST /hunt-pack`, `GET /health`.

## Run locally
```bash
pip install -r requirements.txt
scrapling install            # downloads the stealth browser
cp .env.example .env         # set GROQ_API_KEY and HUNT_SERVICE_SECRET
uvicorn main:app --port 7860
curl -s localhost:7860/health
curl -s -X POST localhost:7860/hunt-pack \
  -H "Content-Type: application/json" -H "X-Hunt-Secret: $HUNT_SERVICE_SECRET" \
  -d '{"url":"https://example.com/report","lang":"en"}' | jq
```

## Deploy — Hugging Face Spaces (Docker, free, browser-capable)
1. Create a new **Space** → SDK **Docker** (16 GB RAM tier handles the browser).
2. Push this `hunt-service/` directory as the Space repo (the `Dockerfile` listens on 7860).
3. In the Space **Settings → Secrets**, set `GROQ_API_KEY` and `HUNT_SERVICE_SECRET`.
4. The public URL becomes the Node backend's `HUNT_SERVICE_URL`.

Note: free Spaces sleep after inactivity — the first request after idle is slow
(cold start). The Node side surfaces a "warming up" state.

## Deploy — Oracle Cloud Always Free (always-on alternative)
Run the container on an Ampere A1 VM (`docker build -t hunt . && docker run -p 7860:7860 --env-file .env hunt`)
behind a reverse proxy with TLS. No cold starts.
