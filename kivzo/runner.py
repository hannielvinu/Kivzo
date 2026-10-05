"""Protected runner: the only component that executes sensitive tools.

The agent never holds credentials. The gateway issues a one-shot, signed execution
capsule for an approved call; the runner verifies it, resolves the secret reference
from the vault, executes once, and marks the nonce consumed. Replays and edited
capsules are rejected.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any

from .tools import call_tool
from .world import World

VAULT = {   # fake credentials - never shown to the agent
    "vault://bank/payment-key": "fake_payment_key_7f3a",
    "vault://smtp/password": "fake_smtp_password_19c2",
    "vault://iot/home-token": "fake_iot_token_55aa",
}
SECRET_REFS = {
    "transfer_money": "vault://bank/payment-key",
    "send_email": "vault://smtp/password",
    "device_control": "vault://iot/home-token",
}


@dataclass
class Capsule:
    tool: str
    args_hash: str
    task_id: str
    nonce: str
    expires: float
    secret_ref: str | None
    sig: str = ""

    def body(self) -> dict:
        return {"tool": self.tool, "args_hash": self.args_hash, "task_id": self.task_id,
                "nonce": self.nonce, "expires": self.expires, "secret_ref": self.secret_ref}

    def public(self) -> dict:
        d = self.body()
        d["nonce"] = self.nonce[:8] + "..."
        d["sig"] = self.sig[:12] + "..."
        return d


def _args_hash(tool: str, args: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps({"tool": tool, "args": args}, sort_keys=True, default=str).encode()).hexdigest()


class ProtectedRunner:
    def __init__(self, world: World, ttl: float = 60.0):
        self.world = world
        self._key = secrets.token_bytes(32)
        self._consumed: set[str] = set()
        self.ttl = ttl
        self.last_capsule: dict[str, tuple[Capsule, dict]] = {}

    def _sign(self, c: Capsule) -> str:
        return hmac.new(self._key, json.dumps(c.body(), sort_keys=True).encode(), hashlib.sha256).hexdigest()

    def issue(self, tool: str, args: dict[str, Any], task_id: str) -> Capsule:
        c = Capsule(tool=tool, args_hash=_args_hash(tool, args), task_id=task_id,
                    nonce=secrets.token_hex(16), expires=time.time() + self.ttl,
                    secret_ref=SECRET_REFS.get(tool))
        c.sig = self._sign(c)
        return c

    def execute(self, capsule: Capsule, args: dict[str, Any]) -> tuple[bool, str, dict]:
        if not hmac.compare_digest(capsule.sig, self._sign(capsule)):
            return False, "capsule signature invalid (capsule was altered)", {}
        if capsule.nonce in self._consumed:
            return False, "capsule already used (replay blocked)", {}
        if time.time() > capsule.expires:
            return False, "capsule expired", {}
        if _args_hash(capsule.tool, args) != capsule.args_hash:
            return False, "arguments differ from the approved call", {}
        self._consumed.add(capsule.nonce)
        if capsule.secret_ref:
            assert capsule.secret_ref in VAULT   # resolved here, never returned to the agent
        out = call_tool(self.world, capsule.tool, args)
        self.last_capsule[capsule.tool] = (capsule, dict(args))
        return True, "executed", out
