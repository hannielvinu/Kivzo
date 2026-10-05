"""KIVZO live console server.

Real-time design: every connected screen subscribes to /api/stream (Server-Sent Events).
Live runs execute in background threads and publish each event as it happens, paced so
people can follow along. Attacks can arrive from any device on the network (/attack).
"""
from __future__ import annotations

import asyncio
import json
import random
import socket
import threading
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import llm, shield
from .attacks import ATTACKS, CARRIER_LABELS, CARRIER_TASK, LEVELS, custom_attack, generated_attacks, interpret
from .bench import RESULTS, run_benchmark, save_all
from .engine import SYSTEMS, run_case
from .gateway import POLICY_PATH, load_policy
from .tasks import TASKS

ROOT = Path(__file__).resolve().parent.parent
WEB = ROOT / "web"
VERSION = str(int(time.time()))

app = FastAPI(title="KIVZO", version="2.0.0")
RESULTS.mkdir(parents=True, exist_ok=True)
(RESULTS / "charts").mkdir(parents=True, exist_ok=True)
app.mount("/charts", StaticFiles(directory=RESULTS / "charts"), name="charts")

_GENERATED = {a.id: a for a in generated_attacks()}
NO_CACHE = {"Cache-Control": "no-store"}


@app.get("/static/{filename:path}")
def static_file(filename: str):
    """Serve static files with no-cache so browsers always get the latest JS/CSS."""
    import mimetypes
    from fastapi.responses import Response
    p = WEB / filename
    if not p.exists() or not p.is_file():
        raise HTTPException(404, "not found")
    mt, _ = mimetypes.guess_type(str(p))
    return Response(content=p.read_bytes(), media_type=mt or "application/octet-stream",
                    headers=NO_CACHE)


# --------------------------------------------------------------------------------------
# broadcast bus
# --------------------------------------------------------------------------------------
class Broker:
    def __init__(self):
        self.subs: set[asyncio.Queue] = set()
        self.loop: asyncio.AbstractEventLoop | None = None

    def publish(self, msg: dict) -> None:
        """Thread-safe: may be called from worker threads."""
        if self.loop is None:
            return
        data = json.dumps(msg, default=str)
        for q in list(self.subs):
            self.loop.call_soon_threadsafe(q.put_nowait, data)


broker = Broker()


@app.on_event("startup")
async def _startup():
    broker.loop = asyncio.get_running_loop()


@app.get("/api/stream")
async def stream(request: Request):
    q: asyncio.Queue = asyncio.Queue()
    broker.subs.add(q)

    async def gen():
        try:
            yield f"data: {json.dumps({'type': 'hello', 'clients': len(broker.subs)})}\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    data = await asyncio.wait_for(q.get(), timeout=15)
                    yield f"data: {data}\n\n"
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
        finally:
            broker.subs.discard(q)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})


# --------------------------------------------------------------------------------------
# live sessions
# --------------------------------------------------------------------------------------
class Session:
    def __init__(self):
        self.id = ""
        self.cancel = threading.Event()
        self.running = False


session = Session()
_session_lock = threading.Lock()


class CustomAttack(BaseModel):
    carrier: str
    text: str
    sender: str = "Attacker Studio"


class LiveReq(BaseModel):
    task_id: str = "T1"
    attack_id: str | None = None
    custom: CustomAttack | None = None
    lanes: list[str] = ["undefended", "kivzo"]
    speed: float = 1.0
    approve: bool = False
    mode: str = "scripted"


def _attack_dict(a) -> dict:
    d = a.to_dict()
    d["intents"] = getattr(a, "intents", None)
    d["carrier_label"] = CARRIER_LABELS.get(a.carrier, a.carrier)
    return d


def _resolve_attack(req: LiveReq):
    if req.custom is not None:
        if not req.custom.text.strip():
            raise HTTPException(400, "attack text is empty")
        try:
            return custom_attack(req.custom.carrier, req.custom.text[:2000], name=f"Live attack from {req.custom.sender}")
        except ValueError as exc:
            raise HTTPException(400, str(exc))
    if req.attack_id:
        a = ATTACKS.get(req.attack_id) or _GENERATED.get(req.attack_id)
        if a is None:
            raise HTTPException(404, f"unknown attack {req.attack_id}")
        return a
    return None


@app.post("/api/live/start")
def live_start(req: LiveReq):
    for s in req.lanes:
        if s not in SYSTEMS:
            raise HTTPException(404, f"unknown system {s}")
    attack = _resolve_attack(req)
    task_id = attack.task_id if attack else req.task_id
    if task_id not in TASKS:
        raise HTTPException(404, "unknown task")
    with _session_lock:
        session.cancel.set()                      # stop whatever was running
        session.cancel = threading.Event()
        session.id = uuid.uuid4().hex[:8]
        session.running = True
        rid, cancel = session.id, session.cancel

    t = TASKS[task_id]
    broker.publish({"type": "start", "run_id": rid, "lanes": [{"system": s, "name": SYSTEMS[s]["name"]} for s in req.lanes],
                    "task": {"id": t.id, "title": t.title, "request": t.request, "expected": t.expected},
                    "attack": _attack_dict(attack) if attack else None, "mode": req.mode})
    remaining = {"n": len(req.lanes)}
    lock = threading.Lock()

    def worker(i: int, system: str):
        def emit(e):
            broker.publish({"type": "ev", "run_id": rid, "lane": i, "system": system, "event": e})
        r = run_case(task_id, attack, system, approve=req.approve, mode=req.mode, emit=emit,
                     speed=max(0.1, min(req.speed, 20.0)), cancel=cancel)
        summary = r.to_dict()
        summary.pop("events", None)
        broker.publish({"type": "lane_done", "run_id": rid, "lane": i, "system": system, "result": summary})
        with lock:
            remaining["n"] -= 1
            last = remaining["n"] == 0
        if last:
            broker.publish({"type": "done", "run_id": rid})
            if session.id == rid:
                session.running = False

    for i, s in enumerate(req.lanes):
        threading.Thread(target=worker, args=(i, s), daemon=True).start()
    return {"run_id": rid, "task_id": task_id}


@app.post("/api/live/stop")
def live_stop():
    session.cancel.set()
    session.running = False
    broker.publish({"type": "stopped", "run_id": session.id})
    return {"ok": True}


class InterpretReq(BaseModel):
    carrier: str
    text: str


@app.post("/api/interpret")
def api_interpret(req: InterpretReq):
    if req.carrier not in CARRIER_LABELS:
        raise HTTPException(400, "unknown carrier")
    actions, overrides, intents = interpret(req.text[:2000], req.carrier)
    return {"intents": intents, "task_id": CARRIER_TASK.get(req.carrier, "T5"),
            "n_actions": len(actions), "overrides": overrides}


@app.post("/api/inject")
def api_inject(req: CustomAttack):
    """An attack submitted from any device (e.g. a judge's phone)."""
    if req.carrier not in CARRIER_LABELS or not req.text.strip():
        raise HTTPException(400, "choose a channel and write some text")
    _, _, intents = interpret(req.text[:2000], req.carrier)
    broker.publish({"type": "incoming", "carrier": req.carrier, "carrier_label": CARRIER_LABELS[req.carrier],
                    "text": req.text[:2000], "sender": (req.sender or "Anonymous")[:40], "intents": intents})
    return {"ok": True, "intents": intents}


# --------------------------------------------------------------------------------------
# live stress test
# --------------------------------------------------------------------------------------
stress = {"running": False, "cancel": threading.Event()}


class StressReq(BaseModel):
    quick: bool = False


@app.post("/api/stress/start")
def stress_start(req: StressReq):
    if stress["running"]:
        return {"ok": False, "reason": "already running"}
    stress["running"] = True
    stress["cancel"] = threading.Event()
    cancel = stress["cancel"]
    systems = list(SYSTEMS)
    broker.publish({"type": "stress_start", "systems": [{"id": s, "name": SYSTEMS[s]["name"]} for s in systems],
                    "quick": req.quick})
    state = {"last": 0.0, "feed": []}

    def on_case(sysname, kind, case, r, acc, done, total):
        if kind != "clean" and sysname in ("undefended", "kivzo") and random.random() < 0.08:
            state["feed"].append({"system": sysname, "id": case.id, "name": case.name, "breached": bool(r.attack_success),
                                  "alert": (r.alerts[0] if r.alerts else "")})
        now = time.time()
        if now - state["last"] > 0.12 or done == total:
            state["last"] = now
            agg = {s: {"atk_ok": a["atk_ok"], "atk_n": a["atk_n"], "clean_ok": a["clean_ok"], "clean_n": a["clean_n"],
                       "util_ok": a["util_ok"],
                       "by_level": {str(k): v for k, v in a["by_level"].items()}} for s, a in acc.items()}
            broker.publish({"type": "stress_progress", "done": done, "total": total, "agg": agg,
                            "feed": state["feed"][-6:]})
            state["feed"] = []

    def worker():
        try:
            res = run_benchmark(systems, generated=not req.quick, on_case=on_case, cancel=cancel)
            if not cancel.is_set():
                res = save_all(res)
            broker.publish({"type": "stress_done", "cancelled": cancel.is_set(), "results": res})
        finally:
            stress["running"] = False

    threading.Thread(target=worker, daemon=True).start()
    return {"ok": True}


@app.post("/api/stress/stop")
def stress_stop():
    stress["cancel"].set()
    return {"ok": True}


# --------------------------------------------------------------------------------------
# sharing: phone attack page + QR code
# --------------------------------------------------------------------------------------
def lan_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


@app.get("/api/share")
def share(request: Request):
    port = request.url.port or 8000
    url = f"http://{lan_ip()}:{port}/attack"
    svg = ""
    try:
        import qrcode
        import qrcode.image.svg
        img = qrcode.make(url, image_factory=qrcode.image.svg.SvgPathImage, box_size=10, border=2)
        svg = img.to_string(encoding="unicode")
    except Exception:
        pass
    return {"url": url, "svg": svg}


def _page(name: str) -> HTMLResponse:
    html = (WEB / name).read_text(encoding="utf-8").replace("{{v}}", VERSION)
    return HTMLResponse(html, headers=NO_CACHE)


@app.get("/")
def index():
    return _page("index.html")


@app.get("/attack")
def attack_page():
    return _page("attack.html")


# --------------------------------------------------------------------------------------
# data endpoints
# --------------------------------------------------------------------------------------
@app.get("/api/status")
def status():
    return {"llm_available": llm.available(), "model": llm.MODEL,
            "shield": shield.backend_name(), "version": "2.0.0"}


@app.get("/api/catalog")
def catalog():
    return {
        "tasks": [{"id": t.id, "title": t.title, "request": t.request, "carrier": t.carrier, "expected": t.expected}
                  for t in TASKS.values()],
        "attacks": [_attack_dict(a) for a in ATTACKS.values()],
        "systems": [{"id": k, "name": v["name"]} for k, v in SYSTEMS.items()],
        "levels": LEVELS,
        "carriers": CARRIER_TASK,
        "carrier_labels": CARRIER_LABELS,
        "generated_count": len(_GENERATED),
    }


class RunReq(BaseModel):
    task_id: str
    attack_id: str | None = None
    system: str = "kivzo"
    approve: bool = False
    mode: str = "scripted"


@app.post("/api/run")
def run(req: RunReq):
    a = ATTACKS.get(req.attack_id) or _GENERATED.get(req.attack_id) if req.attack_id else None
    task_id = a.task_id if a else req.task_id
    if task_id not in TASKS or req.system not in SYSTEMS:
        raise HTTPException(404, "unknown task or system")
    return run_case(task_id, a, req.system, approve=req.approve, mode=req.mode).to_dict()


@app.get("/api/bench")
def bench_latest():
    p = RESULTS / "bench_results.json"
    if not p.exists():
        return JSONResponse({"empty": True})
    return JSONResponse(json.loads(p.read_text(encoding="utf-8")))


@app.get("/api/policy")
def policy():
    return {"text": POLICY_PATH.read_text(encoding="utf-8"), "policy": load_policy()}
