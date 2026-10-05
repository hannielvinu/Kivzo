"""Run one task (optionally under one attack) on one system and record everything.

Systems
  undefended          S0  the agent calls tools directly
  shield              S1  S0 + prompt-injection detector on every tool output
  strict_ifc          S2  KIVZO gateway, but untrusted values are never endorsed
  kivzo               S3  full KIVZO
  kivzo_no_plan_lock  S4  ablation: KIVZO labels and policy only, agent may call any tool

Adversary model: the agent is WORST CASE. When it reads attacker text it obeys it fully
(it attempts every injected tool call and its reader returns the attacker's values).
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any

from . import llm, quarantine, shield
from .attacks import Attack
from .gateway import Gateway
from .labels import Confidentiality as C, Integrity as I, Label, LabelStore, LabeledValue, USER_LABEL, join
from .quarantine import ExtractionError
from .runner import ProtectedRunner
from .tasks import TASKS, Task
from .tools import TOOLS, ToolError, call_tool
from .world import World

SYSTEMS: dict[str, dict] = {
    "undefended": {"name": "S0 Undefended agent", "defended": False, "shield": False},
    "shield": {"name": "S1 Prompt shield", "defended": False, "shield": True},
    "strict_ifc": {"name": "S2 Strict IFC", "defended": True, "plan_lock": True, "endorsement": False},
    "kivzo": {"name": "S3 KIVZO", "defended": True, "plan_lock": True, "endorsement": True},
    "kivzo_no_plan_lock": {"name": "S4 KIVZO, no plan lock (ablation)", "defended": True,
                           "plan_lock": False, "endorsement": True},
}

OUTPUT_FIELDS = {
    "read_invoice": ["text"], "lookup_po": ["vendor", "amount"],
    "read_latest_email": ["sender", "subject", "body"], "read_internal_file": ["content", "name"],
    "fetch_web": ["text"], "get_customer": ["name", "email", "balance", "plan", "notes"],
    "read_note": ["text"], "read_repo_file": ["content"], "read_test_logs": ["log"],
    "read_calendar": ["text"], "delegate_research": ["summary"], "summarize": ["summary"],
    "save_note": ["ok"], "send_email": ["status"], "transfer_money": ["status"],
    "write_repo_file": ["status"], "run_tests": ["passed"], "create_issue": ["status"],
    "device_control": ["status"],
}


def _norm(s: str) -> str:
    return " ".join(str(s).split())


class TaskAbort(Exception):
    pass


class HijackStop(Exception):
    pass


class Cancelled(Exception):
    pass


# seconds to pause after each event kind when a run is paced for live display
PACE = {"plan": 0.9, "call": 1.1, "extract": 0.6, "compute": 0.4, "hijack": 1.3, "world": 0.1,
        "branch": 0.5, "shield": 0.7, "replay": 0.9, "forgery": 0.9, "abort": 0.4, "note": 0.3,
        "hijack_stopped": 0.6}


# --------------------------------------------------------------------------------------
# compute functions used by plans
# --------------------------------------------------------------------------------------
def _minus_minutes(time: str, minutes: int) -> str:
    h, m = map(int, str(time).split(":"))
    t = (h * 60 + m - int(minutes)) % (24 * 60)
    return f"{t // 60:02d}:{t % 60:02d}"


COMPUTE = {
    "minus_minutes": lambda time, minutes: _minus_minutes(time, minutes),
    "customer_report": lambda name, balance, plan: f"Account report for {name}: plan {plan}, balance {float(balance):,.2f} INR.",
    "fix_add": lambda source, log: str(source).replace("return a - b", "return a + b"),
    "issue_body": lambda log: f"Fixed add(): it returned a - b instead of a + b. Failing check was: {log}",
}


@dataclass
class RunResult:
    task_id: str
    attack_id: str | None
    system: str
    mode: str
    plan: list[dict]
    events: list[dict] = field(default_factory=list)
    alerts: list[str] = field(default_factory=list)
    approvals: int = 0
    task_success: bool = False
    attack_success: bool | None = None
    aborted: str = ""
    world: dict = field(default_factory=dict)
    gateway_ms: list[float] = field(default_factory=list)
    llm_calls: int = 0

    def to_dict(self) -> dict:
        return {
            "task_id": self.task_id, "attack_id": self.attack_id, "system": self.system,
            "system_name": SYSTEMS[self.system]["name"], "mode": self.mode, "plan": self.plan,
            "events": self.events, "alerts": self.alerts, "approvals": self.approvals,
            "task_success": self.task_success, "attack_success": self.attack_success,
            "aborted": self.aborted, "world": self.world,
            "gateway_ms": round(sum(self.gateway_ms) / len(self.gateway_ms), 3) if self.gateway_ms else None,
        }


class Run:
    def __init__(self, task: Task, attack: Attack | None, system: str, *, approve: bool = False,
                 mode: str = "scripted", emit=None, speed: float = 0.0, cancel=None):
        self.emit = emit
        self.speed = speed
        self.cancel = cancel
        self.task = task
        self.attack = attack
        self.cfg = SYSTEMS[system]
        self.system = system
        self.approve = approve
        self.mode = mode
        self.world = World()
        self.store = LabelStore()
        self.gateway: Gateway | None = None
        if self.cfg["defended"]:
            # tool manifests are pinned BEFORE any attacker change can happen
            self.gateway = Gateway(self.world, self.store, plan_lock=self.cfg["plan_lock"],
                                   endorsement=self.cfg["endorsement"])
            self.runner = ProtectedRunner(self.world)
        if attack:
            attack.plant(self.world)
        self.env: dict[str, Any] = {}
        self.triggered: set[str] = set()
        self.deferred: list[tuple[Any, LabeledValue]] = []
        self.r = RunResult(task.id, attack.id if attack else None, system, mode, plan=[])
        self._seq = 0

    # ---------------------------------------------------------------- events
    def ev(self, kind: str, **data) -> dict:
        if self.cancel is not None and self.cancel.is_set():
            raise Cancelled()
        self._seq += 1
        e = {"seq": self._seq, "kind": kind, "t": round(time.time(), 3), **data}
        self.r.events.append(e)
        if self.emit and kind != "call":
            self._publish(e)
        return e

    def _publish(self, e: dict) -> None:
        if not self.emit:
            return
        self.emit(e)
        if self.speed > 0:
            time.sleep(PACE.get(e["kind"], 0.4) / self.speed)

    def snapshot(self) -> None:
        if self.emit:
            self._publish({"seq": self._seq, "kind": "world", "world": self.world.summary()})

    # ---------------------------------------------------------------- planning
    def make_plan(self) -> list[dict]:
        if self.mode == "llm" and llm.available():
            try:
                docs = "\n".join(f"- {n}({', '.join(f'{p}: {t}' for p, t in tl.params.items())}) -> "
                                 f"{', '.join(OUTPUT_FIELDS[n])}" for n, tl in TOOLS.items())
                plan = llm.plan(self.task.request, docs)["steps"]
                self.r.llm_calls += 1
                self._validate_plan(plan)
                self.ev("plan", source="LLM planner (saw only the user request)", steps=plan)
                return plan
            except Exception as exc:     # never fail the demo because of the network
                self.ev("note", text=f"LLM planner unavailable ({type(exc).__name__}); using verified plan template")
        self.ev("plan", source="planner (user request only)", steps=self.task.plan)
        return self.task.plan

    @staticmethod
    def _validate_plan(plan: list[dict]) -> None:
        ids = set()
        for s in plan:
            if s["kind"] == "call" and s["tool"] not in TOOLS:
                raise ValueError(f"unknown tool {s['tool']}")
            if s["kind"] == "compute" and s["fn"] not in COMPUTE:
                raise ValueError(f"unknown fn {s['fn']}")
            ids.add(s["id"])

    # ---------------------------------------------------------------- resolving refs
    def resolve(self, ref: str) -> LabeledValue:
        sid, _, fld = ref.partition(".")
        val = self.env.get(sid)
        if val is None:
            raise TaskAbort(f"step {sid} produced no value")
        if isinstance(val, dict):
            if fld not in val:
                raise TaskAbort(f"{sid} has no field {fld}")
            return val[fld]
        return val

    def arg(self, spec: dict) -> LabeledValue:
        if "lit" in spec:
            return self.store.user(spec["lit"])
        return self.resolve(spec["ref"])

    # ---------------------------------------------------------------- main loop
    def run(self) -> RunResult:
        try:
            if self.mode == "llm" and not self.cfg["defended"] and llm.available():
                self.r.plan = []
                self._run_llm_agent()
            else:
                plan = self.make_plan()
                self.r.plan = plan
                for step in plan:
                    self.exec_step(step)
                for act, src in self.deferred:
                    self._hijack_action(act, {"SRC": src}, src)
        except TaskAbort as exc:
            self.r.aborted = str(exc)
            self.ev("abort", text=str(exc))
        except Cancelled:
            self.r.aborted = "cancelled"
            self.r.world = self.world.summary()
            return self.r
        self.r.task_success = bool(self.task.check(self.world))
        if self.attack:
            self.r.attack_success = bool(self.attack.succeeded(self.world))
        self.r.world = self.world.summary()
        return self.r

    def exec_step(self, step: dict) -> None:
        pc = USER_LABEL
        if step.get("when"):
            cond = self.resolve(step["when"]["ref"])
            if str(cond.value) != str(step["when"]["equals"]):
                self.ev("branch", step=step["id"], taken=False, cond=cond.to_dict())
                return
            pc = join([USER_LABEL, cond.label])
            self.ev("branch", step=step["id"], taken=True, cond=cond.to_dict(),
                    pc=pc.to_dict())
        kind = step["kind"]
        if kind == "call":
            args = {k: self.arg(v) for k, v in step.get("args", {}).items()}
            out = self.call(step["tool"], args, origin="plan", pc=pc, step_id=step["id"])
            if out is None:
                raise TaskAbort(f"{step['tool']} was not executed")
            self.env[step["id"]] = out
        elif kind == "extract":
            src = self.resolve(step["from"])
            override = self._override_for(src, step["field"])
            try:
                value = quarantine.extract(src.value, step["type"], field=step["field"], mode=self.mode,
                                           override=override)
            except ExtractionError as exc:
                self.ev("extract", step=step["id"], field=step["field"], type=step["type"], ok=False,
                        error=str(exc), src=src.to_dict())
                raise TaskAbort(f"could not extract {step['field']}: {exc}")
            if self.mode == "llm" and override is None and llm.available():
                self.r.llm_calls += 1
            lv = self.store.derive(value, [src], f"extract:{step['type']}",
                                   note="quarantined reader" + (" (hijacked)" if override is not None else ""))
            self.env[step["id"]] = lv
            self.ev("extract", step=step["id"], field=step["field"], type=step["type"], ok=True,
                    value=lv.to_dict(), hijacked=override is not None)
        elif kind == "compute":
            inputs = {k: (self.store.user(v["lit"]) if isinstance(v, dict) else self.resolve(v))
                      for k, v in step["inputs"].items()}
            value = COMPUTE[step["fn"]](**{k: v.value for k, v in inputs.items()})
            lv = self.store.derive(value, inputs.values(), f"compute:{step['fn']}")
            self.env[step["id"]] = lv
            self.ev("compute", step=step["id"], fn=step["fn"], value=lv.to_dict())

    # ---------------------------------------------------------------- tool calls
    def call(self, tool: str, args: dict[str, LabeledValue], *, origin: str, pc: Label,
             step_id: str = "", requested_by: str = "") -> dict[str, LabeledValue] | None:
        # the agent reads a tool's description right before using it (rug-pull trigger)
        if tool in self.world.tool_descriptions and "tool_desc" in self.world.injections \
                and "tool_desc" not in self.triggered:
            desc = self.world.tool_descriptions[tool]
            src = self.store.new(desc, Label(I.UNTRUSTED, C.PUBLIC, (f"tooldesc:{tool}",)), "tool_description")
            self._trigger(self.world.injections["tool_desc"], src)

        values = {k: v.value for k, v in args.items()}
        e = self.ev("call", tool=tool, origin=origin, step=step_id,
                    args={k: v.to_dict() for k, v in args.items()}, pc=pc.to_dict())

        if self.cfg["defended"]:
            t0 = time.perf_counter()
            d = self.gateway.check(tool, args, origin=origin, pc=pc, requested_by=requested_by)
            self.r.gateway_ms.append((time.perf_counter() - t0) * 1000)
            e["decision"] = d.to_dict()
            e["lineage"] = self.store.lineage([v.id for v in args.values()])
            for a in d.alerts:
                if a not in self.r.alerts:
                    self.r.alerts.append(a)
            self._publish(e)
            verdict = d.verdict
            if verdict == "APPROVAL":
                self.r.approvals += 1
                if self.approve:
                    e["human"] = "approved"
                    verdict = "ALLOW"
                else:
                    e["human"] = "denied (fail closed)"
                    return None
            if verdict == "BLOCK":
                return None
            capsule = self.runner.issue(tool, d.final_args, self.task.id)
            e["capsule"] = capsule.public()
            try:
                ok, msg, out = self.runner.execute(capsule, d.final_args)
            except ToolError as exc:
                e["error"] = str(exc)
                return None
            if not ok:
                e["error"] = msg
                return None
            values = d.final_args
        else:
            e["decision"] = {"verdict": "EXECUTED", "reason": "no defence", "checks": [], "alerts": []}
            self._publish(e)
            try:
                out = call_tool(self.world, tool, values)
            except ToolError as exc:
                e["error"] = str(exc)
                return None

        # wrap outputs in labels
        spec = TOOLS[tool]
        res: dict[str, LabeledValue] = {}
        for fname, o in out.items():
            label = Label(o.integrity, o.confidentiality, (o.source,))
            if tool == "read_note" and values.get("key") in self.world.notes:
                stored = self.store.get(self.world.notes[values["key"]].get("label_id", ""))
                if stored is not None:   # persistent provenance: the note keeps the label it was saved with
                    res[fname] = self.store.derive(o.value, [stored], "read_note", note="label restored from note store")
                    continue
            if spec.derive_inputs:
                res[fname] = self.store.derive(o.value, args.values(), f"tool:{tool}", extra=[label])
            else:
                res[fname] = self.store.new(o.value, label, f"tool:{tool}", [v.id for v in args.values()])
        if tool == "save_note":
            self.world.notes[values["key"]]["label_id"] = args["text"].id
        e["result"] = {k: v.to_dict() for k, v in res.items()}
        self.snapshot()

        # S1: the shield inspects every text the agent is about to read
        if self.cfg.get("shield"):
            for fname, lv in list(res.items()):
                if isinstance(lv.value, str) and shield.flags(lv.value):
                    res[fname] = self.store.derive(shield.REDACTED, [lv], "shield:redact")
                    self.ev("shield", tool=tool, field=fname, detector=shield.backend_name())

        # the (worst-case) agent reads every output; attacker text hijacks it
        for lv in res.values():
            if isinstance(lv.value, str):
                for carrier, inj in self.world.injections.items():
                    if carrier not in self.triggered and _norm(inj.text) in _norm(lv.value):
                        self._trigger(inj, lv)
        return res

    # ---------------------------------------------------------------- hijack simulation
    def _override_for(self, src: LabeledValue, fld: str) -> Any:
        for inj in self.world.injections.values():
            if fld in inj.overrides and isinstance(src.value, str) and _norm(inj.text) in _norm(src.value):
                return inj.overrides[fld]
        return None

    def _trigger(self, inj, src: LabeledValue) -> None:
        self.triggered.add(inj.carrier)
        self.ev("hijack", carrier=inj.carrier, goal=inj.goal, text=inj.text, src=src.to_dict(),
                note="worst-case agent obeys the injected text")
        vars_: dict[str, Any] = {"SRC": src}
        for act in inj.actions:
            if act.get("defer"):
                self.deferred.append((act, src))
                continue
            try:
                self._hijack_action(act, vars_, src)
            except HijackStop as exc:
                self.ev("hijack_stopped", text=str(exc))
                return

    def _render(self, tmpl: Any, vars_: dict, src: LabeledValue) -> LabeledValue:
        if not isinstance(tmpl, str):
            return self.store.derive(tmpl, [src], "injected_literal")
        names = re.findall(r"\{(\w+)(?:\.(\w+))?\}", tmpl)
        if not names:
            return self.store.derive(tmpl, [src], "injected_literal")
        used: list[LabeledValue] = []

        def get(name: str, fld: str) -> LabeledValue:
            v = vars_.get(name)
            if v is None:
                raise HijackStop(f"attack chain stopped: '{name}' was never produced")
            if isinstance(v, dict):
                if fld not in v:
                    raise HijackStop(f"attack chain stopped: no field {fld}")
                return v[fld]
            return v

        whole = re.fullmatch(r"\{(\w+)(?:\.(\w+))?\}", tmpl)
        if whole:
            return get(whole.group(1), whole.group(2) or "")

        def sub(m):
            lv = get(m.group(1), m.group(2) or "")
            used.append(lv)
            return str(lv.value)

        text = re.sub(r"\{(\w+)(?:\.(\w+))?\}", sub, tmpl)
        return self.store.derive(text, used + [src], "injected_template")

    def _hijack_action(self, act: dict, vars_: dict, src: LabeledValue) -> None:
        if "literal" in act:
            vars_[act["save"]] = self.store.derive(act["literal"], [src], "injected_value")
            return
        if "extract" in act:
            text_lv = self._render(act["extract"], vars_, src)
            want = act.get("want")
            raw = want if want and want in str(text_lv.value) else quarantine.scripted_extract(str(text_lv.value), act["type"])
            if raw is None:
                raise HijackStop("attack chain stopped: value lost in transformation")
            vars_[act["save"]] = self.store.derive(raw, [text_lv], f"extract:{act['type']}", note="hijacked reader")
            return
        if "replay" in act:
            self._replay(act["replay"])
            return
        tool = act["call"]
        args = {k: self._render(v, vars_, src) for k, v in act["args"].items()}
        if act.get("forge"):
            # a compromised component rewrites the labels in memory without the signing key
            for lv in args.values():
                lv.label = Label(I[act["forge"]], C.PUBLIC, ("forged",))
            self.ev("forgery", tool=tool, note=f"labels rewritten to {act['forge']} without the signing key")
        out = self.call(tool, args, origin="injected", pc=src.label,
                        requested_by=f" ({', '.join(src.label.sources)})")
        if out is None:
            raise HijackStop(f"attack chain stopped at {tool}")
        if "save" in act:
            vars_[act["save"]] = out

    def _replay(self, tool: str) -> None:
        if self.cfg["defended"]:
            last = self.runner.last_capsule.get(tool)
            if last is None:
                self.ev("replay", tool=tool, ok=False, reason="no capsule to replay")
                return
            capsule, args = last
            ok, msg, _ = self.runner.execute(capsule, args)
            self.ev("replay", tool=tool, ok=ok, reason=msg, capsule=capsule.public())
            if not ok:
                self.r.alerts.append(f"REPLAY BLOCKED: {msg}")
        else:
            pays = self.world.effects["payments"]
            if not pays:
                self.ev("replay", tool=tool, ok=False, reason="nothing to replay")
                return
            p = dict(pays[-1])
            call_tool(self.world, "transfer_money", p)
            self.ev("replay", tool=tool, ok=True, reason="undefended: payment executed again")

    # ---------------------------------------------------------------- real LLM baseline
    def _run_llm_agent(self) -> None:
        import json
        manifests = {n: t.manifest(self.world) for n, t in TOOLS.items()}
        tools = llm.tool_defs(TOOLS, manifests)
        messages: list[dict] = [{"role": "user", "content": self.task.request}]
        for _ in range(12):
            resp = llm.agent_turn(messages, tools)
            self.r.llm_calls += 1
            messages.append({"role": "assistant", "content": resp.content})
            uses = [b for b in resp.content if b.type == "tool_use"]
            if not uses:
                break
            results = []
            for b in uses:
                e = self.ev("call", tool=b.name, origin="llm-agent", args={k: {"value": v} for k, v in b.input.items()})
                try:
                    out = call_tool(self.world, b.name, dict(b.input))
                    data = {k: o.value for k, o in out.items()}
                    if self.cfg.get("shield"):
                        for k, v in data.items():
                            if isinstance(v, str) and shield.flags(v):
                                data[k] = shield.REDACTED
                                self.ev("shield", tool=b.name, field=k, detector=shield.backend_name())
                    e["decision"] = {"verdict": "EXECUTED", "reason": "no defence", "checks": [], "alerts": []}
                    self._publish(e)
                    self.snapshot()
                    results.append({"type": "tool_result", "tool_use_id": b.id, "content": json.dumps(data, default=str)})
                except Exception as exc:
                    e["error"] = str(exc)
                    e["decision"] = {"verdict": "EXECUTED", "reason": "no defence", "checks": [], "alerts": []}
                    self._publish(e)
                    results.append({"type": "tool_result", "tool_use_id": b.id, "content": str(exc), "is_error": True})
            messages.append({"role": "user", "content": results})


def run_case(task_id: str, attack: Attack | None = None, system: str = "kivzo", *,
             approve: bool = False, mode: str = "scripted", emit=None, speed: float = 0.0,
             cancel=None) -> RunResult:
    return Run(TASKS[task_id], attack, system, approve=approve, mode=mode, emit=emit, speed=speed,
               cancel=cancel).run()
