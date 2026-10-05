# KIVZO — Provenance-Aware Defence for Tool-Using AI Agents

**Future Forge Buildathon 2026 · Track AG03 — The Agent That Survives a Poisoned Tool**

KIVZO is a real-time security framework that defends AI agents against prompt injection attacks embedded in emails, documents, web pages, and sub-agent outputs. Unlike keyword blocklists, KIVZO tracks *where every value came from* and enforces policy on that lineage — so an attacker cannot trick the agent by rephrasing, translating, or indirecting an instruction.

---

## Live Demo

```
python run.py
```

Open `http://localhost:8000` — judges can scan the QR code on the page and attack from their phone in real time.

---

## What It Does

| Without KIVZO | With KIVZO |
|---|---|
| Agent reads attacker IBAN from email body | KIVZO labels the IBAN as `UNTRUSTED` |
| Agent calls `transfer_money(to_iban="EVIL...")` | Gateway intercepts: corroborates against vendor registry |
| Money sent to attacker | Attacker IBAN rejected; real vendor IBAN used |

KIVZO implements **information-flow control (IFC)** with corroborated endorsement — a third path between "block everything" and "trust everything":

1. **Label every value at source** — HMAC-signed integrity + confidentiality labels, stored out-of-band so content cannot forge them
2. **Quarantine untrusted text** — a sandboxed reader extracts only typed fields (IBAN, amount, PO number) — no free text passes through
3. **Corroborate before endorsing** — an UNTRUSTED IBAN is admitted only when the vendor registry confirms it matches the plan-bound supplier
4. **One-shot execution capsules** — signed, nonce-protected capsules prevent replay attacks
5. **Tool manifest pinning** — tool descriptions are hashed at session start; a changed description is blocked (rug-pull defence)

---

## Architecture

```
User Request (USER / PUBLIC)
      │
      ▼
  PLANNER  ←── sees only the user's request, never untrusted content
      │
      ▼
KIVZO GATEWAY  ←── 6 ordered checks on every tool call
  1. Tool integrity     (manifest hash pinned at session start)
  2. Task scope         (call must match the plan)
  3. Label signature    (HMAC integrity verification)
  4. Decision context   (PC-taint: calls inside untrusted branches inherit taint)
  5. Argument provenance (per-policy: allow / endorse / approve / block)
  6. Confidentiality sink (no secret data in outbound URLs or emails)
      │
      ├──► TOOLS (19 mock tools covering payments, email, files, devices, CI)
      │
      └──► READER (quarantined — returns typed fields only, no raw text)
```

---

## Benchmark Results

| System | Attack Success Rate | Task Completion | Description |
|---|---|---|---|
| S0 Undefended | ~94% | 100% | Baseline — no defence |
| S1 Prompt Shield | ~61% | 98% | Keyword/DeBERTa scan |
| S2 Strict IFC | ~3% | 71% | Labels but no endorsement |
| **S3 KIVZO** | **~2%** | **97%** | Full system |
| S4 KIVZO no plan lock | ~4% | 94% | Ablation — labels only |

Benchmark covers 7 tasks × 14 named attacks + 630 generated variants (6 goals × 7 carriers × 3 hop counts × 5 rewording levels), run under a worst-case adversary that obeys every injected instruction.

---

## Attack Coverage

| Attack | Vector | KIVZO response |
|---|---|---|
| A1 Direct injection | Email | Label: UNTRUSTED — block |
| A2 Reworded (Hindi) | Email | Free-text interpreter extracts IBAN regardless of language |
| A3 Poisoned README | Git README | Quarantine — extracts no actionable values |
| A6 EchoLeak URL exfil | Web page | Confidentiality sink — SECRET data blocked from URLs |
| A8 BEC bank-detail swap | Invoice | VALUE OVERRIDDEN — attacker IBAN rejected, real vendor IBAN used |
| A9 MCP rug pull | Tool description | Manifest hash mismatch — blocked at check 1 |
| A10 Label forgery | Any | HMAC verify fails — content cannot forge trust level |
| A11 Compromised sub-agent | Sub-agent output | Sub-agent output crosses boundary as UNTRUSTED |
| A14 Replay | Capsule | One-shot nonce consumed — replay rejected |

---

## Project Structure

```
kivzo/
├── kivzo/
│   ├── labels.py        # HMAC-signed integrity + confidentiality labels
│   ├── gateway.py       # 6-check gateway (the core defence)
│   ├── quarantine.py    # Typed-field extractor for untrusted text
│   ├── corroborate.py   # System-of-record corroborators (vendor, PO, etc.)
│   ├── runner.py        # One-shot execution capsules
│   ├── engine.py        # Run driver — scripted + LLM modes
│   ├── attacks.py       # 14 named + 630 generated attacks; free-text interpreter
│   ├── tasks.py         # 7 legitimate tasks with deterministic success checks
│   ├── world.py         # Mock company world (payments, email, files, devices)
│   ├── tools.py         # 19 mock tools with provenance metadata
│   ├── bench.py         # Benchmark runner with Wilson CI
│   ├── server.py        # FastAPI server — SSE live stream, phone attack endpoint
│   └── policy.yaml      # Declarative per-tool argument policy
├── web/
│   ├── index.html       # Live console (tabbed: Arena, Stress Test, Trust Model, Library)
│   ├── style.css        # Dark live-console theme
│   ├── app.js           # Real-time SSE client
│   └── attack.html      # Phone attack pad (served at /attack)
├── tests/
│   └── test_kivzo.py    # 33 tests — all pass
├── docs/
│   ├── ARCHITECTURE.md
│   ├── TRUST_MODEL.md
│   ├── DEMO_SCRIPT.md
│   └── JUDGE_QA.md
├── run.py               # Server launcher (double-click start.bat on Windows)
├── bench.py             # CLI benchmark entry point
└── requirements.txt
```

---

## Quick Start

```bash
pip install -r requirements.txt
python run.py
```

For LLM mode (uses Gemini API):
```bash
set GEMINI_API_KEY=AIzaSy...
python run.py
```

Run the benchmark:
```bash
python bench.py
```

Run tests:
```bash
pytest tests/
```

---

## Key Innovation: Corroborated Endorsement

Strict IFC blocks T1, T2, and T6 because legitimate task arguments (vendor IBANs, email addresses) arrive in untrusted documents. KIVZO solves this with **corroborated endorsement**:

1. Planner locks the expected vendor into the plan at task start
2. Quarantine reader extracts the typed IBAN from the document
3. Corroborator checks: does this IBAN match the plan-bound vendor's registered account?
4. If yes → endorse (admit as TRUSTED_SYSTEM); if no → block or override with the trusted value

This gives KIVZO a 97% task completion rate vs 71% for strict IFC, while keeping attack success near 2%.

---

## Author

**Hanniel Vinu**
Future Forge Buildathon 2026 · VELS University Thiruvanmiyur Campus
