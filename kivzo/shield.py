"""Baseline S1: a prompt-injection 'shield' that inspects tool output text.

Default back-end is a keyword/regex detector built from phrases commonly used in
open-source injection filters. If `transformers` is installed and KIVZO_SHIELD=protectai,
the ProtectAI DeBERTa v3 prompt-injection classifier is used instead.

Flagged text is removed before the agent sees it, which also removes any legitimate data
in that text. That is how detectors behave in practice.
"""
from __future__ import annotations

import os
import re

PATTERNS = [
    r"ignore (all |any )?(previous|prior|above|earlier) (instructions|messages)",
    r"disregard (all |the |any )?(previous|prior|above|instructions)",
    r"forget (all |your )?(previous |prior )?instructions",
    r"you (must|are) now",
    r"new instructions?:",
    r"do not (tell|inform|alert) the user",
    r"(system|developer) prompt",
    r"\bjailbreak\b",
    r"override (your|the) (rules|instructions|guidelines)",
    r"act as (an? )?(admin|administrator|developer)",
]
_RE = re.compile("|".join(PATTERNS), re.I)

_backend = os.environ.get("KIVZO_SHIELD", "keyword")
_clf = None


def backend_name() -> str:
    return "ProtectAI deberta-v3-base-prompt-injection-v2" if _backend == "protectai" else "keyword/regex detector"


def _protectai(text: str) -> bool:
    global _clf
    if _clf is None:
        from transformers import pipeline
        _clf = pipeline("text-classification", model="protectai/deberta-v3-base-prompt-injection-v2",
                        truncation=True, max_length=512)
    res = _clf(text)[0]
    return res["label"] == "INJECTION" and res["score"] > 0.5


def flags(text: str) -> bool:
    if not isinstance(text, str) or not text:
        return False
    if _backend == "protectai":
        try:
            return _protectai(text)
        except Exception:
            pass
    return bool(_RE.search(text))


REDACTED = "[removed by prompt shield]"
