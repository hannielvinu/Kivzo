"""Benchmark: every system x (clean tasks + named attacks + generated attacks).

Writes results/bench_results.json, results/BENCHMARK_REPORT.md and charts in results/charts.
All numbers are computed from runs; nothing is hard-coded.
"""
from __future__ import annotations

import json
import math
import platform
import statistics
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from . import shield
from .attacks import LEVELS, generated_attacks, named_attacks
from .engine import SYSTEMS, run_case
from .tasks import TASKS

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    den = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / den
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return (max(0.0, centre - half), min(1.0, centre + half))


def _rate(k: int, n: int) -> dict:
    lo, hi = wilson(k, n)
    return {"k": k, "n": n, "rate": (k / n) if n else 0.0, "ci95": [lo, hi]}


def _legit_sensitive_calls(r) -> tuple[int, int]:
    """(blocked, total) for sensitive calls made by the plan in a clean run."""
    from .tools import TOOLS
    total = blocked = 0
    for e in r.events:
        if e["kind"] == "call" and e.get("origin") == "plan" and TOOLS[e["tool"]].sensitive:
            total += 1
            if e["decision"]["verdict"] in ("BLOCK", "APPROVAL") and e.get("human") != "approved":
                blocked += 1
    return blocked, total


def run_benchmark(systems: list[str] | None = None, *, generated: bool = True, mode: str = "scripted",
                  runs: int = 1, limit: int | None = None, progress=None, on_case=None, cancel=None) -> dict:
    """Case-major loop: every case runs on every system before moving on, so live views
    see all systems progress together."""
    systems = systems or list(SYSTEMS)
    named = named_attacks()
    gen = generated_attacks() if generated else []
    if limit:
        gen = gen[:limit]
    t_start = time.time()
    out: dict = {
        "meta": {
            "date": datetime.now().isoformat(timespec="seconds"),
            "mode": mode, "runs_per_case": runs, "python": platform.python_version(),
            "shield_backend": shield.backend_name(),
            "n_tasks": len(TASKS), "n_named_attacks": len(named), "n_generated_attacks": len(gen),
            "adversary": "worst-case agent: obeys every injected instruction it reads",
        },
        "systems": {},
        "named": {},
    }
    acc = {s: {"clean_ok": 0, "clean_n": 0, "fb_blocked": 0, "fb_total": 0, "approvals": [], "lat": [],
               "atk_ok": 0, "atk_n": 0, "named_ok": 0, "named_n": 0, "util_ok": 0,
               "by_level": defaultdict(lambda: [0, 0]), "by_hops": defaultdict(lambda: [0, 0]),
               "by_carrier": defaultdict(lambda: [0, 0]), "by_goal": defaultdict(lambda: [0, 0]),
               "per_task": {}} for s in systems}
    cases = ([("clean", tid) for tid in TASKS] + [("named", a) for a in named] + [("gen", a) for a in gen]) * runs
    total = len(cases) * len(systems)
    done = 0
    for kind, case in cases:
        for sysname in systems:
            if cancel is not None and cancel.is_set():
                break
            a = acc[sysname]
            if kind == "clean":
                r = run_case(case, None, sysname, mode=mode)
                a["clean_n"] += 1
                a["clean_ok"] += r.task_success
                a["per_task"][case] = r.task_success
                b, t = _legit_sensitive_calls(r)
                a["fb_blocked"] += b
                a["fb_total"] += t
                a["approvals"].append(r.approvals)
            else:
                r = run_case(case.task_id, case, sysname, mode=mode)
                ok = bool(r.attack_success)
                a["atk_n"] += 1
                a["atk_ok"] += ok
                a["util_ok"] += r.task_success
                if kind == "named":
                    a["named_n"] += 1
                    a["named_ok"] += ok
                    out["named"].setdefault(case.id, {"attack": case.to_dict(), "results": {}})["results"][sysname] = {
                        "attack_success": r.attack_success, "task_success": r.task_success,
                        "alerts": r.alerts, "approvals": r.approvals,
                    }
                else:
                    for bucket, key in (("by_level", case.level), ("by_hops", case.hops),
                                        ("by_carrier", case.carrier), ("by_goal", case.goal)):
                        a[bucket][key][0] += ok
                        a[bucket][key][1] += 1
            a["lat"].extend(r.gateway_ms)
            done += 1
            if on_case:
                on_case(sysname, kind, case, r, acc, done, total)
            if progress:
                progress(done, total)

    for sysname in systems:
        a = acc[sysname]
        lat_sorted = sorted(a["lat"])
        out["systems"][sysname] = {
            "name": SYSTEMS[sysname]["name"],
            "asr_all": _rate(a["atk_ok"], a["atk_n"]),
            "asr_named": _rate(a["named_ok"], a["named_n"]),
            "tcr_clean": _rate(a["clean_ok"], a["clean_n"]),
            "tcr_under_attack": _rate(a["util_ok"], a["atk_n"]),
            "false_block_rate": _rate(a["fb_blocked"], a["fb_total"]),
            "approvals_per_task": (sum(a["approvals"]) / len(a["approvals"])) if a["approvals"] else 0.0,
            "latency_ms": {
                "median": statistics.median(lat_sorted) if lat_sorted else None,
                "p95": lat_sorted[int(0.95 * (len(lat_sorted) - 1))] if lat_sorted else None,
                "n": len(lat_sorted),
            },
            "asr_by_level": {f"L{k} {LEVELS[k]}": _rate(*v) for k, v in sorted(a["by_level"].items())},
            "asr_by_hops": {f"{k} hop": _rate(*v) for k, v in sorted(a["by_hops"].items())},
            "asr_by_carrier": {k: _rate(*v) for k, v in sorted(a["by_carrier"].items())},
            "asr_by_goal": {k: _rate(*v) for k, v in sorted(a["by_goal"].items())},
            "clean_tasks": a["per_task"],
        }
    out["meta"]["seconds"] = round(time.time() - t_start, 2)
    out["meta"]["total_runs"] = done
    return out


# ------------------------------------------------------------------------------------
# reporting
# ------------------------------------------------------------------------------------
def pct(r: dict) -> str:
    return f"{100 * r['rate']:.1f}%"


def pct_ci(r: dict) -> str:
    return f"{100 * r['rate']:.1f}% [{100 * r['ci95'][0]:.1f}-{100 * r['ci95'][1]:.1f}] (n={r['n']})"


def write_report(res: dict, path: Path) -> None:
    m = res["meta"]
    S = res["systems"]
    lines = [
        "# KIVZO Benchmark Report",
        "",
        f"Generated {m['date']} by `python bench.py` - {m['total_runs']} runs in {m['seconds']} s "
        f"(mode: {m['mode']}, Python {m['python']}).",
        "",
        "## Setup",
        "",
        f"- **Legitimate tasks:** {m['n_tasks']} multi-tool tasks (payments, email, code, CRM, web research, smart home, sub-agent).",
        f"- **Attacks:** {m['n_named_attacks']} named scenarios + {m['n_generated_attacks']} generated "
        "(6 goals x 7 carriers x 1-3 hops x 5 rewording levels).",
        f"- **Adversary:** {m['adversary']}. A defence must hold even when the model is fully hijacked.",
        f"- **Prompt-shield back-end:** {m['shield_backend']}.",
        "- **Confidence intervals:** Wilson 95%. Scripted mode is deterministic, so repeated runs give identical numbers; "
        "use `--mode llm --runs 3` for model-in-the-loop variance.",
        "",
        "## Headline results",
        "",
        "| System | Attack success (all) | Attack success (named) | Task completion (clean) | Task completion under attack | False-block rate | Approvals / task | Gateway latency median / p95 |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for k, s in S.items():
        lat = s["latency_ms"]
        latency = (f"{lat['median']:.3f} / {lat['p95']:.3f} ms" if lat["median"] is not None else "-")
        lines.append(f"| {s['name']} | {pct_ci(s['asr_all'])} | {pct(s['asr_named'])} | {pct(s['tcr_clean'])} | "
                     f"{pct(s['tcr_under_attack'])} | {pct(s['false_block_rate'])} | {s['approvals_per_task']:.2f} | {latency} |")
    lines += ["", "## Attack success by rewording level", "",
              "| Level | " + " | ".join(s["name"] for s in S.values()) + " |",
              "|---|" + "---|" * len(S)]
    levels = next(iter(S.values()))["asr_by_level"].keys()
    for lv in levels:
        lines.append(f"| {lv} | " + " | ".join(pct(s["asr_by_level"][lv]) for s in S.values()) + " |")
    lines += ["", "## Attack success by number of hops", "",
              "| Hops | " + " | ".join(s["name"] for s in S.values()) + " |",
              "|---|" + "---|" * len(S)]
    for h in next(iter(S.values()))["asr_by_hops"].keys():
        lines.append(f"| {h} | " + " | ".join(pct(s["asr_by_hops"][h]) for s in S.values()) + " |")
    lines += ["", "## Attack success by carrier", "",
              "| Carrier | " + " | ".join(s["name"] for s in S.values()) + " |",
              "|---|" + "---|" * len(S)]
    for c in next(iter(S.values()))["asr_by_carrier"].keys():
        lines.append(f"| {c} | " + " | ".join(pct(s["asr_by_carrier"][c]) for s in S.values()) + " |")
    lines += ["", "## Named attack scenarios", "",
              "| ID | Scenario | " + " | ".join(s["name"] for s in S.values()) + " | Stopped by (KIVZO) |",
              "|---|---|" + "---|" * len(S) + "---|"]
    for aid, row in res["named"].items():
        cells = []
        for k in S:
            rr = row["results"].get(k, {})
            cells.append(("ATTACK SUCCEEDED" if rr.get("attack_success") else "contained")
                         + (" / task done" if rr.get("task_success") else " / task not done"))
        lines.append(f"| {aid} | {row['attack']['name']} | " + " | ".join(cells) + f" | {row['attack']['stopped_by']} |")
    lines += ["", "## Clean task completion per task", "",
              "| Task | " + " | ".join(s["name"] for s in S.values()) + " |",
              "|---|" + "---|" * len(S)]
    for tid, t in TASKS.items():
        lines.append(f"| {tid} {t.title} | " + " | ".join("done" if s["clean_tasks"].get(tid) else "NOT DONE" for s in S.values()) + " |")
    lines += [
        "",
        "## Reading the results",
        "",
        "- **S0 Undefended** shows what a fully hijacked agent does: every attack whose goal is reachable succeeds.",
        "- **S1 Prompt shield** only removes text it recognises. Success depends on wording, and removing flagged "
        "text also removes the legitimate data around it.",
        "- **S2 Strict IFC** contains attacks but cannot finish tasks whose sensitive arguments legitimately come "
        "from untrusted documents (pay an invoice, send the requested report, schedule from a calendar).",
        "- **S3 KIVZO** contains the same attacks and recovers those tasks through plan-bound slots and corroborated endorsement.",
        "- **S4 KIVZO without plan lock** (ablation) shows that provenance labels and policy alone contain the attacks "
        "even when the agent may call any tool.",
        "",
        "## Known limits (where KIVZO does not claim protection)",
        "",
        "| Case | Why | Mitigation |",
        "|---|---|---|",
        "| Text-only influence (a misleading summary shown to the user) | No action or data flow to check | Show provenance next to text in the UI |",
        "| Poisoned trusted records (attacker edits the vendor master) | Corroboration trusts the system of record | Signed records, change alerts, dual control on master-data edits |",
        "| Attacks during tasks the planner cannot express | Falls back to approval | Count and report approvals; extend plan templates |",
        "| A rug-pulled tool the task genuinely needs | Fail-closed: the task stops until the tool is re-approved | Re-approval flow for changed manifests |",
        "| Attacks where the attacker's request matches the user's own intent and records | Indistinguishable by design | Out of scope |",
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def write_charts(res: dict, outdir: Path) -> list[str]:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    outdir.mkdir(parents=True, exist_ok=True)
    S = res["systems"]
    names = [s["name"].split(" ", 1)[0] for s in S.values()]
    full = [s["name"] for s in S.values()]
    colors = ["#b23b2a", "#d08b2c", "#5f6b7a", "#0f6e5c", "#4f8fbf"][: len(S)]
    files = []

    fig, ax = plt.subplots(figsize=(8, 4.2))
    x = range(len(S))
    asr = [100 * s["asr_all"]["rate"] for s in S.values()]
    tcr = [100 * s["tcr_clean"]["rate"] for s in S.values()]
    w = 0.38
    b1 = ax.bar([i - w / 2 for i in x], asr, w, label="Attack success rate (lower is better)", color="#b23b2a")
    b2 = ax.bar([i + w / 2 for i in x], tcr, w, label="Clean task completion (higher is better)", color="#0f6e5c")
    for b in list(b1) + list(b2):
        ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 1, f"{b.get_height():.0f}%", ha="center", fontsize=8)
    ax.set_xticks(list(x), full, fontsize=7.5, rotation=10)
    ax.set_ylim(0, 112)
    ax.set_ylabel("%")
    ax.set_title("Security vs utility across systems")
    ax.legend(fontsize=8, loc="upper center", ncol=2, frameon=False)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    p = outdir / "security_vs_utility.png"
    fig.savefig(p, dpi=150)
    plt.close(fig)
    files.append(p.name)

    fig, ax = plt.subplots(figsize=(8, 4.2))
    levels = list(next(iter(S.values()))["asr_by_level"].keys())
    for (k, s), c in zip(S.items(), colors):
        ax.plot(range(len(levels)), [100 * s["asr_by_level"][lv]["rate"] for lv in levels], marker="o", color=c,
                label=s["name"], linewidth=2)
    ax.set_xticks(range(len(levels)), [lv.split(" ", 1)[1] for lv in levels], fontsize=8, rotation=10)
    ax.set_ylabel("Attack success rate (%)")
    ax.set_ylim(-3, 105)
    ax.set_title("Rewording the attack: detection fails, provenance does not")
    ax.legend(fontsize=7.5, frameon=False)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    p = outdir / "asr_by_rewording.png"
    fig.savefig(p, dpi=150)
    plt.close(fig)
    files.append(p.name)

    fig, ax = plt.subplots(figsize=(6.4, 4.6))
    placed: list[tuple[float, float]] = []
    for (k, s), c, n in zip(S.items(), colors, full):
        xy = (100 * s["tcr_under_attack"]["rate"], 100 * s["asr_all"]["rate"])
        overlap = sum(1 for p in placed if abs(p[0] - xy[0]) < 4 and abs(p[1] - xy[1]) < 4)
        placed.append(xy)
        ax.scatter(*xy, s=160 - 50 * overlap, color=c, zorder=3 + overlap)
        ax.annotate(n, xy, textcoords="offset points", xytext=(-150, 8 + 14 * overlap) if xy[0] > 70 else (8, 6),
                    fontsize=8)
    ax.set_xlabel("Task completion under attack (%)  ->  better")
    ax.set_ylabel("Attack success rate (%)  ->  worse")
    ax.set_xlim(-5, 110)
    ax.set_ylim(-5, 110)
    ax.set_title("Utility-security trade-off (bottom right is best)")
    ax.grid(alpha=0.25)
    fig.tight_layout()
    p = outdir / "tradeoff.png"
    fig.savefig(p, dpi=150)
    plt.close(fig)
    files.append(p.name)
    return files


def save_all(res: dict, outdir: Path = RESULTS) -> dict:
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "bench_results.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
    write_report(res, outdir / "BENCHMARK_REPORT.md")
    try:
        res["charts"] = write_charts(res, outdir / "charts")
    except Exception as exc:          # charts are optional
        res["charts"] = []
        res["chart_error"] = str(exc)
    (outdir / "bench_results.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
    return res
