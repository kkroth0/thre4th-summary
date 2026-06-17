"""LLM analysis + structured validation for the Threat Hunting pipeline.

Sends the scraped report to Groq (Llama 3.3 70B, temperature 0, JSON mode) and
coerces the answer into a strict Pydantic schema. If validation fails, the
validation error is fed back to the model for a corrected retry. Every IOC is
defanged before it leaves this module.
"""
from __future__ import annotations

import json
import logging
import os
import re
from typing import List, Literal

from pydantic import BaseModel, ValidationError, field_validator, model_validator

logger = logging.getLogger("hunt.analyzer")

GROQ_MODELS = ["llama-3.3-70b-versatile", "llama-3.1-8b-instant", "gemma2-9b-it"]
MAX_RETRIES = 2

_IPV4 = re.compile(r"^(25[0-5]|2[0-4]\d|[01]?\d?\d)(\.(25[0-5]|2[0-4]\d|[01]?\d?\d)){3}$")
_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9](-?[a-z0-9])*\.)+[a-z]{2,}$")
_URL = re.compile(r"^https?://[^\s]+$", re.I)
_HASH = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
_TTP = re.compile(r"^T\d{4}(\.\d{3})?$")


# ---- defang / refang ---------------------------------------------------------
def refang(v: str) -> str:
    return (
        str(v)
        .replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
        .replace("[:]", ":").replace("[@]", "@").replace("[at]", "@")
        .replace("hxxp", "http")  # hxxps -> https too
        .strip()
    )


def defang(v: str) -> str:
    """Neutralise an IOC so it can't be clicked/auto-linked when saved/shared."""
    out = str(v)
    out = out.replace("https://", "hxxps://").replace("http://", "hxxp://")
    out = out.replace(".", "[.]").replace("@", "[@]")
    return out


# ---- structured schema (the "Pydantic" requirement) --------------------------
class IOC(BaseModel):
    type: Literal["ip", "domain", "url", "hash"]
    value: str

    @model_validator(mode="after")
    def _validate_and_defang(self) -> "IOC":
        canonical = refang(self.value)
        patterns = {"ip": _IPV4, "domain": _DOMAIN, "url": _URL, "hash": _HASH}
        check = canonical.lower() if self.type in ("domain", "hash") else canonical
        if not patterns[self.type].match(check):
            raise ValueError(f"IOC value '{self.value}' is not a valid {self.type}")
        # Store the defanged form — IOCs never leave this service in live form.
        object.__setattr__(self, "value", defang(canonical))
        return self


class DetectionQuery(BaseModel):
    kql: str
    sigma: str = ""

    @field_validator("kql")
    @classmethod
    def _kql_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("detection_query.kql must not be empty")
        return v.strip()


class HuntPack(BaseModel):
    threat_actor: str
    ttp_mitre: List[str]
    ioc_list: List[IOC]
    hunting_hypothesis: str
    detection_query: DetectionQuery
    executive_brief: str  # CISO / coordinator business-risk language
    soc_summary: str       # technical SOC language

    @field_validator("ttp_mitre")
    @classmethod
    def _valid_ttps(cls, v: List[str]) -> List[str]:
        bad = [t for t in v if not _TTP.match(str(t))]
        if bad:
            raise ValueError(f"invalid MITRE ATT&CK codes (need Txxxx or Txxxx.yyy): {bad}")
        return v

    @field_validator("hunting_hypothesis")
    @classmethod
    def _hyp_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("hunting_hypothesis must not be empty")
        return v.strip()


def _system_prompt(lang: str) -> str:
    out_lang = "English" if lang == "en" else "Português (Brasil)"
    return (
        "You are a Senior Cyber Threat Intelligence analyst and Microsoft Sentinel "
        "detection engineer. Read the security report and produce a Threat Hunting Pack. "
        "Respond with ONLY a JSON object with EXACTLY these keys:\n"
        '- "threat_actor": named actor/group, or "Unknown".\n'
        '- "ttp_mitre": array of MITRE ATT&CK technique IDs (format Txxxx or Txxxx.yyy), '
        "based strictly on behaviours described.\n"
        '- "ioc_list": array of objects {"type": one of ip|domain|url|hash, "value": the indicator}. '
        "Use the real (refanged) value; do not invent IOCs.\n"
        '- "hunting_hypothesis": one concrete, testable threat-hunting hypothesis a SOC can pursue.\n'
        '- "detection_query": object {"kql": a ready-to-run Microsoft Sentinel KQL query derived from '
        'the TTP/IOCs, "sigma": an equivalent Sigma rule in YAML}. The KQL MUST NOT be empty.\n'
        '- "executive_brief": 2-3 sentences for a CISO / SOC coordinator — business risk, impact and '
        "why it matters, NO jargon.\n"
        '- "soc_summary": 2-3 technical sentences for SOC analysts — attack chain and what to look for.\n'
        f"Write executive_brief, soc_summary and hunting_hypothesis in {out_lang}. "
        "Keep ttp_mitre, IOCs and the queries technical/untranslated. Respond ONLY the JSON."
    )


class Analyzer:
    """Wraps the Groq client and the validate-or-retry loop."""

    def __init__(self) -> None:
        api_key = os.environ.get("GROQ_API_KEY")
        # Imported lazily so the schema + FastAPI app load even without the SDK.
        if api_key:
            from groq import AsyncGroq
            self._client = AsyncGroq(api_key=api_key)
        else:
            self._client = None

    @property
    def available(self) -> bool:
        return self._client is not None

    async def _complete(self, messages: list[dict]) -> dict | None:
        """Call Groq with the model fallback chain; return parsed JSON or None."""
        for model in GROQ_MODELS:
            try:
                resp = await self._client.chat.completions.create(
                    model=model,
                    temperature=0,
                    response_format={"type": "json_object"},
                    messages=messages,
                    timeout=30,
                )
                content = resp.choices[0].message.content
                if content:
                    return json.loads(content)
            except Exception as exc:  # noqa: BLE001 - try next model
                logger.warning("Groq model %s failed: %s", model, exc)
        return None

    async def analyze(self, title: str, content: str, lang: str) -> HuntPack:
        if not self.available:
            raise RuntimeError("GROQ_API_KEY not configured")

        messages = [
            {"role": "system", "content": _system_prompt(lang)},
            {"role": "user", "content": f"Title: {title}\n\nReport:\n{content[:12000]}"},
        ]

        last_error: Exception | None = None
        for attempt in range(MAX_RETRIES + 1):
            raw = await self._complete(messages)
            if raw is None:
                raise RuntimeError("LLM returned no parseable output")
            try:
                return HuntPack.model_validate(raw)
            except ValidationError as err:
                last_error = err
                logger.info("validation failed (attempt %d): %s", attempt + 1, err)
                # Feed the error back so the model self-corrects (the retry requirement).
                messages.append({"role": "assistant", "content": json.dumps(raw)})
                messages.append({
                    "role": "user",
                    "content": (
                        "Your previous JSON failed schema validation with these errors:\n"
                        f"{err}\n"
                        "Return ONLY corrected JSON that satisfies every constraint."
                    ),
                })

        raise last_error or RuntimeError("hunt pack validation failed")
