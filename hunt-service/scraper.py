"""Article ingestion for the Threat Hunting pipeline.

Uses Scrapling to fetch and clean the readable text of a security report. Tries
the lightweight fetcher first (fast, cheap) and falls back to the stealth
browser fetcher for bot-protected / JS-heavy targets (Cloudflare, etc.).

The whole module is defensive: any failure degrades to an empty string so the
caller can decide how to proceed instead of crashing the request.
"""
from __future__ import annotations

import asyncio
import logging

logger = logging.getLogger("hunt.scraper")

# Boilerplate paragraphs we never want in the analysed text.
_BOILERPLATE = (
    "advertisement", "scroll to continue", "related:", "subscribe", "sign up",
    "sponsored", "cookie", "share this", "read more", "tags:", "follow us",
    "newsletter",
)

MAX_CHARS = 12000


def _clean(adaptor) -> str:
    """Extract readable <p> text from a Scrapling page adaptor."""
    try:
        # Prefer the densest content root, mirroring the Node extractor.
        root = adaptor.css_first("article") or adaptor.css_first("main") or adaptor
        paras: list[str] = []
        for p in root.css("p"):
            text = " ".join(p.get_all_text(strip=True).split())
            if len(text) <= 45:
                continue
            low = text.lower()
            if any(low.startswith(b) for b in _BOILERPLATE):
                continue
            paras.append(text)
        return "\n\n".join(paras)[:MAX_CHARS]
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("clean failed: %s", exc)
        return ""


def _fetch_lightweight(url: str) -> str:
    from scrapling.fetchers import StealthyFetcher

    # Lightweight stealth fetch (no full browser); fast and usually enough.
    page = StealthyFetcher.fetch(url, headless=True, network_idle=False, timeout=20000)
    if page is None or getattr(page, "status", 200) >= 400:
        return ""
    return _clean(page)


def _fetch_browser(url: str) -> str:
    from scrapling.fetchers import PlayWrightFetcher

    # Full stealth browser for bot-protected / JS-rendered pages.
    page = PlayWrightFetcher.fetch(
        url,
        headless=True,
        network_idle=True,
        stealth=True,
        timeout=35000,
    )
    if page is None or getattr(page, "status", 200) >= 400:
        return ""
    return _clean(page)


async def scrape_article(url: str) -> str:
    """Return cleaned article text for *url*, or '' if it can't be fetched.

    Runs the blocking Scrapling fetchers in a thread so the FastAPI event loop
    stays responsive. Lightweight first, browser fallback when it comes back thin.
    """
    try:
        text = await asyncio.to_thread(_fetch_lightweight, url)
    except Exception as exc:
        logger.warning("lightweight fetch failed for %s: %s", url, exc)
        text = ""

    # If the cheap path returned little, escalate to the full stealth browser.
    if len(text) < 400:
        try:
            browser_text = await asyncio.to_thread(_fetch_browser, url)
            if len(browser_text) > len(text):
                text = browser_text
        except Exception as exc:
            logger.warning("browser fetch failed for %s: %s", url, exc)

    return text
