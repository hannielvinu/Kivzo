"""The KIVZO gateway: deterministic authorisation for every tool call.

No LLM is involved here. A call is checked for:
  1. tool integrity      - the tool's manifest still matches the hash pinned at session start
  2. task scope          - the call is a step of the plan made from the user's request
  3. label integrity     - every argument's label carries a valid signature
  4. decision context    - was the decision to call influenced by untrusted data (pc taint)?
  5. argument provenance - may a value of this integrity fill this argument?
  6. confidentiality     - does data flowing into this call exceed the destination's clearance?
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .corroborate import CORROBORATORS
from .labels import Confidentiality as C, Integrity as I, Label, LabelStore, LabeledValue, join
from .tools import TOOLS
from .world import World

POLICY_PATH = Path(__file__).with_name("policy.yaml")

RANK = {"ALLOW": 0, "ENDORSE": 1, "OVERRIDE": 2, "APPROVAL": 3, "BLOCK": 4}


def load_policy(path: Path = POLICY_PATH) -> dict:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


@dataclass
class Check:
    name: str
    ok: bool
    detail: str
    verdict: str = "ALLOW"

    def to_dict(self) -> dict:
        return {"name": self.name, "ok": self.ok, "detail": self.detail, "verdict": self.verdict}


@dataclass
class Decision:
    tool: str
    verdict: str = "ALLOW"
    checks: list[Check] = field(default_factory=list)
    final_args: dict[str, Any] = field(default_factory=dict)
    alerts: list[str] = field(default_factory=list)

    def add(self, check: Check) -> None:
        self.checks.append(check)
        if RANK[check.verdict] > RANK[self.verdict]:
            self.verdict = check.verdict

    @property
    def reason(self) -> str:
        bad = [c for c in self.checks if not c.ok]
        if bad:
            worst = max(bad, key=lambda c: RANK[c.verdict])
            return worst.detail
        notable = [c.detail for c in self.checks if c.verdict in ("OVERRIDE", "ENDORSE")]
        return "; ".join(notable) if notable else "all checks passed"

    def to_dict(self) -> dict:
        return {"tool": self.tool, "verdict": self.verdict, "reason": self.reason,
                "checks": [c.to_dict() for c in self.checks], "alerts": list(self.alerts),
                "final_args": {k: (v if not isinstance(v, str) or len(v) < 200 else v[:197] + "...")
                               for k, v in self.final_args.items()}}


class Gateway:
    def __init__(self, world: World, store: LabelStore, *, plan_lock: bool = True,
                 endorsement: bool = True, policy: dict | None = None):
        self.world = world
        self.store = store
        self.plan_lock = plan_lock
        self.endorsement = endorsement
        self.policy = policy or load_policy()
        self.pinned = {name: t.manifest_hash() for name, t in TOOLS.items()}

    def check(self, tool: str, args: dict[str, LabeledValue], *, origin: str, pc: Label,
              requested_by: str = "") -> Decision:
        d = self._check(tool, args, origin=origin, pc=pc, requested_by=requested_by)
        if d.verdict == "BLOCK" and not d.alerts:
            d.alerts.append(f"BLOCKED {tool}: {d.reason}")
        return d

    def _check(self, tool: str, args: dict[str, LabeledValue], *, origin: str, pc: Label,
               requested_by: str = "") -> Decision:
        d = Decision(tool=tool, final_args={k: v.value for k, v in args.items()})
        spec = TOOLS.get(tool)
        if spec is None:
            d.add(Check("tool exists", False, f"unknown tool '{tool}'", "BLOCK"))
            return d

        # 1. tool integrity
        current = spec.manifest_hash(self.world)
        if current != self.pinned[tool]:
            d.add(Check("tool integrity", False,
                        f"'{tool}' changed its description/schema after it was approved (rug pull)", "BLOCK"))
            d.alerts.append(f"TOOL TAMPERING: manifest of {tool} no longer matches pinned hash")
        else:
            d.add(Check("tool integrity", True, "manifest matches pinned hash"))

        # 2. task scope
        if origin != "plan":
            if self.plan_lock:
                what = ("requested data unrelated to the task" if tool in ("read_internal_file", "read_note")
                        else "is not part of the user's plan")
                d.add(Check("task scope", False,
                            f"call to {tool} {what}; it was requested by untrusted content{requested_by}", "BLOCK"))
                d.alerts.append(f"TASK-SCOPE VIOLATION: untrusted content tried to call {tool}")
            else:
                d.add(Check("task scope", True, "plan lock disabled (ablation mode)"))
        else:
            d.add(Check("task scope", True, "call is a step of the user's plan"))

        # 3. label integrity
        forged = [k for k, v in args.items() if not self.store.verify(v)]
        if forged:
            d.add(Check("label integrity", False,
                        f"label signature invalid for {', '.join(forged)} (forged or tampered label)", "BLOCK"))
            d.alerts.append(f"LABEL FORGERY: tampered provenance on {tool}({', '.join(forged)})")
        else:
            d.add(Check("label integrity", True, "all labels verified"))

        tpol = self.policy["tools"].get(tool)
        if tpol is None:
            if spec.sensitive:
                d.add(Check("policy", False, f"no policy for sensitive tool {tool}", "BLOCK"))
            return d

        # 4. decision context (program-counter taint)
        if pc.integrity <= I.INTERNAL:
            rule = tpol.get("pc_untrusted", "block")
            allow_when = tpol.get("pc_allow_when") or {}
            if allow_when and all(
                str(args[a].value) in vals and args[a].label.integrity >= I.TRUSTED_SYSTEM
                for a, vals in allow_when.items() if a in args
            ):
                rule = "allow"
            verdict = {"allow": "ALLOW", "approve": "APPROVAL", "block": "BLOCK"}[rule]
            d.add(Check("decision context", verdict == "ALLOW",
                        f"the decision to call {tool} depends on {pc.integrity.name} data "
                        f"({', '.join(pc.sources) or 'unknown'}) -> {rule}", verdict))
        else:
            d.add(Check("decision context", True, "call decided from the user's request only"))

        # 5. argument provenance
        for name, lv in args.items():
            rule = (tpol.get("args") or {}).get(name, {"default": "allow"})
            level = lv.label.integrity.name
            action = rule.get(level, rule.get("default", "block"))
            src = ", ".join(lv.label.sources) or "?"
            if action == "allow":
                d.add(Check(f"arg:{name}", True, f"{name} from {level} ({src}) allowed"))
            elif action == "block":
                d.add(Check(f"arg:{name}", False, f"{name} comes from {level} data ({src}); not allowed here", "BLOCK"))
            elif action == "approve":
                d.add(Check(f"arg:{name}", False, f"{name} from {level} data ({src}) needs approval", "APPROVAL"))
            elif action == "endorse":
                self._endorse(d, name, lv, rule, args, origin)

        # 6. confidentiality sink
        sink = tpol.get("sink")
        if sink:
            data = [args[a] for a in sink.get("data_args", []) if a in args]
            flow = join([v.label for v in data]) if data else None
            if flow is not None:
                if "recipient_arg" in sink:
                    to = str(d.final_args.get(sink["recipient_arg"], "")).lower()
                    contact = self.world.d["address_book"].get(to)
                    clearance = C[contact["clearance"]] if contact else C.PUBLIC
                    dest = f"recipient {to} (clearance {clearance.name})"
                else:
                    clearance = C[sink["max_confidentiality"]]
                    dest = f"{tool} (max {clearance.name})"
                if flow.confidentiality > clearance:
                    d.add(Check("confidentiality", False,
                                f"{flow.confidentiality.name} data from {', '.join(flow.sources)} would flow to {dest}",
                                "BLOCK"))
                    d.alerts.append(f"EXFILTRATION BLOCKED: {flow.confidentiality.name} data -> {dest}")
                else:
                    d.add(Check("confidentiality", True,
                                f"{flow.confidentiality.name} data may flow to {dest}"))
        return d

    def _endorse(self, d: Decision, name: str, lv: LabeledValue, rule: dict, args: dict[str, LabeledValue],
                 origin: str) -> None:
        level = lv.label.integrity.name
        src = ", ".join(lv.label.sources) or "?"
        on_fail = rule.get("on_fail", "block")
        if not self.endorsement:
            verdict = "APPROVAL" if on_fail == "approve" else "BLOCK"
            d.add(Check(f"arg:{name}", False,
                        f"{name} comes from {level} data ({src}); strict IFC does not endorse untrusted values",
                        verdict))
            return
        corr = CORROBORATORS[rule["corroborate"]]
        ok, detail, trusted = corr(self.world, lv.value, {k: v.value for k, v in args.items()})
        if ok:
            d.add(Check(f"arg:{name}", True, f"{name} from {level} ({src}) endorsed: {detail}", "ENDORSE"))
            return
        if on_fail == "override" and trusted is not None and origin == "plan":
            d.final_args[name] = trusted
            d.add(Check(f"arg:{name}", True,
                        f"{detail}; replaced with the trusted record's value", "OVERRIDE"))
            d.alerts.append(f"VALUE OVERRIDDEN: {name}={lv.value} rejected, used trusted {trusted}")
        elif on_fail == "approve":
            d.add(Check(f"arg:{name}", False, f"{name} not corroborated: {detail}", "APPROVAL"))
        else:
            d.add(Check(f"arg:{name}", False, f"{name} not corroborated: {detail}", "BLOCK"))
            d.alerts.append(f"BLOCKED: {name} - {detail}")
