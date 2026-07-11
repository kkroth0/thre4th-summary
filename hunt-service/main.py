"""FastAPI entrypoint for the Threat Hunting microservice.

Flow: scrape (Scrapling) -> analyze (OpenRouter + Pydantic validate/retry) -> defanged
structured Hunt Pack. Intended to sit behind the Node backend, which proxies to
it and enforces the advisory allowlist; this service additionally requires a
shared secret so it can't be called by arbitrary clients.
"""
from __future__ import annotations

import logging
import os

from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from analyzer import Analyzer
from scraper import scrape_article

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("hunt.main")

app = FastAPI(title="ThreatSumm4ry Hunt Service", version="1.0.0")
analyzer = Analyzer()

HUNT_SECRET = os.environ.get("HUNT_SERVICE_SECRET", "")


class HuntRequest(BaseModel):
    url: str
    lang: str = Field(default="en")
    title: str = Field(default="")


def _check_secret(provided: str | None) -> None:
    # If a secret is configured, require it. (Defence in depth on top of the
    # Node allowlist proxy.)
    if HUNT_SECRET and provided != HUNT_SECRET:
        raise HTTPException(status_code=401, detail="invalid hunt secret")


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "llm": analyzer.available}


@app.post("/hunt-pack")
async def hunt_pack(req: HuntRequest, x_hunt_secret: str | None = Header(default=None)) -> dict:
    _check_secret(x_hunt_secret)

    if not analyzer.available:
        raise HTTPException(status_code=503, detail="LLM not configured")
    if not (req.url.startswith("http://") or req.url.startswith("https://")):
        raise HTTPException(status_code=400, detail="url must be http(s)")

    content = await scrape_article(req.url)
    if not content or len(content) < 120:
        raise HTTPException(status_code=422, detail="could not extract enough article text to analyse")

    lang = "en" if req.lang == "en" else "pt"
    title = req.title or req.url

    try:
        pack = await analyzer.analyze(title, content, lang)
    except Exception as exc:  # noqa: BLE001
        logger.exception("analysis failed for %s", req.url)
        raise HTTPException(status_code=502, detail=f"analysis failed: {exc}") from exc

    return {
        "available": True,
        "scraped_chars": len(content),
        "lang": lang,
        **pack.model_dump(),
    }
