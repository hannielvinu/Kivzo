"""Provenance labels.

Every value that enters the system is wrapped in a LabeledValue. Labels have two axes:

  integrity        - who may steer actions with this value (USER is highest)
  confidentiality  - who may see this value (SECRET is highest)

Labels are assigned by the label store, never parsed from content, and every label
record is HMAC-signed so a compromised component cannot silently upgrade it.
"""
from __future__ import annotations

import hashlib
import hmac
import itertools
import json
import secrets
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Iterable


class Integrity(IntEnum):
    UNTRUSTED = 0        # web, email bodies, tool output, tool descriptions, other agents
    INTERNAL = 1         # internal content written by other people (logs, CRM records)
    TRUSTED_SYSTEM = 2   # system-of-record data: vendor master, address book, mail headers
    USER = 3             # the principal's own request


class Confidentiality(IntEnum):
    PUBLIC = 0
    INTERNAL = 1
    SECRET = 2


@dataclass(frozen=True)
class Label:
    integrity: Integrity
    confidentiality: Confidentiality
    sources: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "integrity": self.integrity.name,
            "confidentiality": self.confidentiality.name,
            "sources": list(self.sources),
        }

    @property
    def short(self) -> str:
        return f"{self.integrity.name}/{self.confidentiality.name}"


def join(labels: Iterable[Label]) -> Label:
    """Most restrictive combination: lowest integrity, highest confidentiality."""
    labels = list(labels)
    if not labels:
        return Label(Integrity.USER, Confidentiality.PUBLIC, ())
    integ = min(l.integrity for l in labels)
    conf = max(l.confidentiality for l in labels)
    srcs: list[str] = []
    for l in labels:
        for s in l.sources:
            if s not in srcs:
                srcs.append(s)
    return Label(integ, conf, tuple(srcs))


USER_LABEL = Label(Integrity.USER, Confidentiality.PUBLIC, ("user:request",))


@dataclass
class LabeledValue:
    id: str
    value: Any
    label: Label
    op: str                       # how this value was produced
    parents: tuple[str, ...] = ()
    note: str = ""
    sig: str = ""

    def to_dict(self) -> dict:
        v = self.value
        if isinstance(v, str) and len(v) > 160:
            v = v[:157] + "..."
        return {
            "id": self.id,
            "value": v,
            "label": self.label.to_dict(),
            "op": self.op,
            "parents": list(self.parents),
            "note": self.note,
        }


def _digest(value: Any) -> str:
    try:
        raw = json.dumps(value, sort_keys=True, default=str)
    except TypeError:
        raw = repr(value)
    return hashlib.sha256(raw.encode()).hexdigest()


class LabelStore:
    """Owns every LabeledValue for one run. Only the store can create or relabel values."""

    def __init__(self, key: bytes | None = None):
        self._key = key or secrets.token_bytes(32)
        self._values: dict[str, LabeledValue] = {}
        self._ids = itertools.count(1)

    # -- creation -------------------------------------------------------------------
    def new(self, value: Any, label: Label, op: str, parents: Iterable[str] = (), note: str = "") -> LabeledValue:
        lv = LabeledValue(id=f"v{next(self._ids)}", value=value, label=label, op=op,
                          parents=tuple(parents), note=note)
        lv.sig = self._sign(lv)
        self._values[lv.id] = lv
        return lv

    def derive(self, value: Any, inputs: Iterable[LabeledValue], op: str, extra: Iterable[Label] = (), note: str = "") -> LabeledValue:
        """A value computed from other values inherits the join of their labels."""
        inputs = list(inputs)
        label = join([i.label for i in inputs] + list(extra))
        return self.new(value, label, op, [i.id for i in inputs], note)

    def user(self, value: Any, note: str = "") -> LabeledValue:
        return self.new(value, USER_LABEL, "user_literal", (), note)

    # -- integrity ------------------------------------------------------------------
    def _sign(self, lv: LabeledValue) -> str:
        payload = json.dumps({
            "id": lv.id,
            "i": int(lv.label.integrity),
            "c": int(lv.label.confidentiality),
            "s": list(lv.label.sources),
            "op": lv.op,
            "p": list(lv.parents),
            "d": _digest(lv.value),
        }, sort_keys=True).encode()
        return hmac.new(self._key, payload, hashlib.sha256).hexdigest()

    def verify(self, lv: LabeledValue) -> bool:
        stored = self._values.get(lv.id)
        if stored is None or stored is not lv:
            return False
        return hmac.compare_digest(lv.sig, self._sign(lv))

    # -- lineage --------------------------------------------------------------------
    def get(self, vid: str) -> LabeledValue | None:
        return self._values.get(vid)

    def lineage(self, roots: Iterable[str]) -> dict:
        """Nodes and edges for every ancestor of the given value ids."""
        seen: dict[str, LabeledValue] = {}
        stack = list(roots)
        while stack:
            vid = stack.pop()
            if vid in seen or vid not in self._values:
                continue
            lv = self._values[vid]
            seen[vid] = lv
            stack.extend(lv.parents)
        nodes = [lv.to_dict() for lv in sorted(seen.values(), key=lambda x: int(x.id[1:]))]
        edges = [{"from": p, "to": lv.id} for lv in seen.values() for p in lv.parents if p in seen]
        return {"nodes": nodes, "edges": edges}

    def depth(self, vid: str) -> int:
        """Number of derivation hops from the value back to its furthest source."""
        lv = self._values.get(vid)
        if lv is None or not lv.parents:
            return 0
        return 1 + max(self.depth(p) for p in lv.parents)
