"""Quarantined reader: turns untrusted text into ONE typed value.

It has no tools and its output is validated against a strict type, so an instruction
hidden in the text has nowhere to go except into a value that the gateway then checks.

Two back-ends:
  scripted - deterministic parsers (default; reproducible benchmark)
  llm      - Gemini with a structured-output schema (used with --mode llm)
"""
from __future__ import annotations

import re
from typing import Any

from . import llm

TYPES: dict[str, re.Pattern] = {
    "iban": re.compile(r"^[A-Z]{2}\d{2}[A-Z]{4}\d{10}$"),
    "amount": re.compile(r"^\d+(\.\d{1,2})?$"),
    "po": re.compile(r"^PO-\d{3}$"),
    "email": re.compile(r"^[\w.+-]+@[\w-]+(\.[\w-]+)+$"),
    "filename": re.compile(r"^[\w-]+\.(pdf|csv|xlsx|env|txt)$"),
    "time": re.compile(r"^\d{2}:\d{2}$"),
    "location": re.compile(r"^(office|remote|offsite)$"),
    "vendor": re.compile(r"^[A-Z]{3,12}$"),
    "url": re.compile(r"^https://[\w.-]+(/[\w./?=&%-]*)?$"),
    "device": re.compile(r"^(front_door|heater)$"),
}

_PARSERS: dict[str, list[re.Pattern]] = {
    "iban": [re.compile(r"Pay to:\s*([A-Z]{2}\d{2}[A-Z]{4}\d{10})"), re.compile(r"\b([A-Z]{2}\d{2}[A-Z]{4}\d{10})\b")],
    "amount": [re.compile(r"Amount due:\s*([\d,]+(?:\.\d{1,2})?)"), re.compile(r"\b(\d{3,}(?:\.\d{1,2})?)\b")],
    "po": [re.compile(r"\b(PO-\d{3})\b")],
    "email": [re.compile(r"\b([\w.+-]+@[\w-]+(?:\.[\w-]+)+)\b")],
    "filename": [re.compile(r"\b([\w-]+\.(?:pdf|csv|xlsx|env|txt))\b")],
    "time": [re.compile(r"Time:\s*(\d{2}:\d{2})"), re.compile(r"\b(\d{2}:\d{2})\b")],
    "location": [re.compile(r"Location:\s*(\w+)")],
    "url": [re.compile(r"(https://[\w.-]+(?:/[\w./?=&%-]*)?)")],
    "device": [re.compile(r"\b(front_door|heater)\b")],
}


class ExtractionError(Exception):
    pass


def _parse_vendor(text: str) -> str | None:
    m = re.search(r"From:\s*([^\n]+)", text)
    hay = (m.group(1) if m else text).upper()
    for code in ("ACME", "GLOBEX"):
        if code in hay:
            return code
    return None


def scripted_extract(text: str, typ: str) -> str | None:
    if typ == "vendor":
        return _parse_vendor(text)
    for pat in _PARSERS.get(typ, []):
        m = pat.search(text)
        if m:
            return m.group(1).replace(",", "") if typ == "amount" else m.group(1)
    return None


def validate(value: Any, typ: str) -> Any:
    if value is None:
        raise ExtractionError(f"no {typ} found")
    s = str(value).strip()
    pat = TYPES.get(typ)
    if pat and not pat.fullmatch(s):
        raise ExtractionError(f"value {s[:60]!r} is not a valid {typ}")
    if typ == "amount":
        return round(float(s), 2)
    return s


def extract(text: str, typ: str, *, field: str, mode: str = "scripted",
            override: Any = None) -> Any:
    """Return a typed value. `override` simulates a fully hijacked reader (worst case)."""
    if override is not None:
        raw = override
    elif mode == "llm" and llm.available():
        try:
            raw = llm.extract_field(text, field, typ)
        except Exception:
            raw = scripted_extract(text, typ)   # keep the demo running if the API is unreachable
    else:
        raw = scripted_extract(text, typ)
    return validate(raw, typ)
