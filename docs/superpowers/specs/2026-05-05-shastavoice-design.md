# ShastaVoice — Voice-Driven Compliance Console

**Status:** Approved design, pre-implementation
**Date:** 2026-05-05
**Owner:** kkmookhey
**Repo:** kkmookhey/shasta (sibling module, not a separate repo)

## Purpose

Add a voice-driven dynamic dashboard to Shasta as an opt-in capability. Users run `python -m shasta.voice` after a scan and have a conversational, hands-free interface to their compliance posture — query findings across SOC 2 / ISO 27001 / HIPAA / ISO 42001 / EU AI Act, drill into specific controls and resources, and perform light writes (manage the risk register).

This is positioned as an **open-source credibility / UX showcase** for Shasta — proof that AI-native compliance can include a voice modality, not just a CLI and an HTML dashboard. It reuses ~70% of the [VoiceApp prototype](../../../../../VoiceApp/docs/superpowers/specs/2026-05-05-voiceapp-design.md)'s architecture, adapted to Shasta's real data layer.

## Non-goals

- Demo / seeded fake data. Voice runs on the user's actual `data/shasta.db`. No `--demo` mode.
- Long-running operations over voice — `/scan`, `/report`, `/remediate`, `/policy-gen` stay in slash-commands. The voice assistant points users to those when asked.
- Production multi-user auth. Localhost-only, matches Shasta's existing dashboard.
- Replacing the existing HTML dashboard. Voice runs alongside it on a separate port.
- Mobile / responsive layout. Desktop-first.

## Locked decisions (from brainstorming)

| Decision | Choice | Why |
|---|---|---|
| Where the code lives | Sibling module `src/shasta/voice/` inside the Shasta repo | First-class Shasta feature without coupling to the existing HTML dashboard |
| Data source | Real `ShastaDB` (no mocks, no demo mode) | "Full functionality on actual scan results" — no curated demo layer |
| Scope | Read everything + light writes (risk register operations) | Snappy demo without async/job-tracking complexity for long-running ops |
| Voice architecture | OpenAI Realtime API (browser-direct WebRTC) | Same as VoiceApp — sub-second latency, natural barge-in |
| Visual language | Distinct dark Transilience theme (not Shasta's existing light/indigo dashboard) | Voice = "command center" experience, deserves its own signature; reuses VoiceApp components |
| Distribution | `pip install shasta[voice]` extra; pre-built React bundle ships in the wheel | No Node required at runtime; voice is opt-in |
| Auth | None (localhost only) | Matches Shasta's existing dashboard pattern; production seam documented |

## Architecture

```
Shasta repo (one git tree)

src/shasta/
  ├── aws/, azure/, compliance/, db/, evidence/, …    ← existing
  ├── dashboard/    ← existing HTML dashboard (Jinja, port 8080)
  │
  └── voice/        ← NEW SIBLING MODULE
        ├── __init__.py
        ├── __main__.py        ← `python -m shasta.voice` entrypoint
        ├── cli.py             ← registers `shasta voice` subcommand
        ├── app.py             ← FastAPI sub-app (separate from dashboard's)
        ├── session.py         ← /session/token endpoint
        ├── realtime_config.py ← system prompt + tool schemas + VAD
        ├── store.py           ← thin facade over ShastaDB + scoring
        ├── observability.py   ← structured tool-call logging
        ├── tools/
        │   ├── __init__.py
        │   ├── findings.py    ← list_findings, get_finding, …
        │   ├── scores.py      ← get_compliance_score, get_trend, …
        │   ├── controls.py    ← get_control_summary
        │   ├── risks.py       ← list/get/add/update risk items
        │   ├── scans.py       ← list_scans, get_latest_scan
        │   └── router.py      ← FastAPI router exposing /tools/*
        └── web/
              ├── dist/        ← pre-built React bundle (committed)
              └── src/         ← React source (built via `npm run build`)

At runtime:

┌────────────────────────┐                  ┌──────────────────────────┐
│  Browser (localhost)   │ ◄── WebRTC ──►  │   OpenAI Realtime API    │
│  React app served by   │                  └──────────────────────────┘
│  the FastAPI sub-app   │           ▲              │
└──────────┬─────────────┘           │              │ tool_call events
           │ POST /tools/{name}      │ ephemeral    ▼
           ▼                         │ token
┌────────────────────────────────────┴──────────┐
│  shasta voice  →  FastAPI on :8090            │
│  • serves /  (React bundle from web/dist/)    │
│  • POST /session/token  → mints OpenAI key    │
│  • POST /tools/*         → executes tool      │
└──────────┬────────────────────────────────────┘
           │ (calls)
           ▼
┌──────────────────────────────────────────────┐
│  shasta.voice.store   (thin facade)           │
│   ├── ShastaDB  (existing, unchanged)         │
│   ├── compliance.scorer  (existing)           │
│   ├── compliance.iso27001_scorer (existing)   │
│   ├── compliance.hipaa_scorer (existing)      │
│   └── compliance.mapper / iso27001_mapper /   │
│        hipaa_mapper (existing)                │
└──────────────────────────────────────────────┘
```

**Key architectural principles:**

1. **No mock layer.** Voice reads what the dashboard reads. The store facade composes existing Shasta modules; it does not introduce a second source of truth.
2. **Pre-built React bundle in the pip wheel.** Users do not need Node.js installed to run `shasta voice`. Source lives in `web/src/`, build artifact in `web/dist/`, both committed. CI rebuilds on PRs that touch `web/src/`. (Documented exception to "don't commit build artifacts" — justified because zero-Node distribution is a non-negotiable for the credibility-demo audience.)
3. **Separate FastAPI app + separate port.** Voice console at `:8090`, existing dashboard stays at `:8080`. They can run side by side. Sharing one app would couple lifecycles unnecessarily.
4. **Voice is read-mostly + risk-register writes only.** Heavy operations (scans, reports, Terraform, policy gen) explicitly remain in slash-commands. The system prompt teaches the model to redirect.
5. **No auth in MVP.** Localhost-only. The seam where production-grade auth would plug in is `app.py` middleware + `session.py` token-mint identity binding.

**Production seams (documented in code):**
- `app.py` CORS origin and `session.py` user identity would derive from JWT in a hosted scenario.
- `store.py` is the only place that touches `ShastaDB` directly — single point of substitution if Shasta ever moves to a different storage backend.

## Components

### Python (`src/shasta/voice/`)

| Module | Responsibility |
|---|---|
| `cli.py` | The `main()` function called by `__main__.py` (so `python -m shasta.voice` works). Argparse-based — validates `OPENAI_API_KEY`, checks `data/shasta.db` has at least one scan, starts uvicorn on `:8090`, opens browser unless `--no-open`. Mirrors the existing `shasta.dashboard.__main__` pattern. |
| `app.py` | FastAPI app, CORS for `http://localhost:8090` only, mounts `web/dist/` as static files at `/`, includes session and tools routers. |
| `session.py` | `POST /session/token` — calls OpenAI's `/v1/realtime/sessions` with the payload from `realtime_config.build_session_payload()`, returns ephemeral client secret. Returns 502 on OpenAI failure, 500 if `OPENAI_API_KEY` missing. |
| `realtime_config.py` | The Distiller system prompt (compliance-flavored persona), JSON schemas for the 14 tools, server VAD config, voice selection, `input_audio_transcription` enabled. Single source of truth. |
| `store.py` | Thin facade over `ShastaDB` and scoring/mapper functions. Methods: `list_findings(...)`, `get_finding(id)`, `get_score(framework)`, `get_multi_framework_score()`, `get_score_trend(framework, limit)`, `get_control_summary(framework, control_id?)`, `list_risk_items(...)`, `get_risk_item(id)`, `add_risk_item(...)`, `update_risk(...)`, `list_scans(limit)`, `get_latest_scan()`. Each returns Pydantic-validated objects. |
| `observability.py` | Structured JSON logging via the `shasta.voice` logger. Logs every tool call with `tool_name`, `args`, `latency_ms`, `result_size`. |
| `tools/findings.py` | `list_findings`, `get_finding`, `list_top_blockers`, `get_resource_findings` — thin wrappers returning JSON dicts. |
| `tools/scores.py` | `get_compliance_score`, `get_multi_framework_score`, `get_score_trend`, `get_ai_governance_score`. |
| `tools/controls.py` | `get_control_summary`, `get_control_findings`. |
| `tools/risks.py` | `list_risk_items`, `get_risk_item`, `add_risk_item`, `update_risk`. The two write paths. |
| `tools/scans.py` | `list_scans`, `get_latest_scan`. |
| `tools/router.py` | FastAPI router under `/tools` prefix; one endpoint per tool with Pydantic request models for input validation; wraps each call with `_timed()` for observability. |

### React (`src/shasta/voice/web/src/`)

Reused unchanged from VoiceApp:
- `voice/connection.ts`, `voice/events.ts`, `state/session.ts`
- `components/Header.tsx`, `MicChrome.tsx`, `Transcript.tsx`, `cards/SeverityBadge.tsx`, `cards/ActionToast.tsx`
- `styles/tokens.css`, `global.css`

Updated for Shasta:
- `tools/types.ts` — replaced with Shasta types (`Finding`, `FindingDetail`, `ComplianceScore`, `MultiFrameworkScore`, `ScoreTrend`, `ControlSummary`, `RiskItem`, `Scan`, `ActionResult`).
- `tools/relay.ts` — `KNOWN_TOOLS` set updated to the 14 Shasta tools.
- `voice/cardDispatcher.ts` — maps each Shasta tool name to its corresponding card kind (or `null` for tools that don't mount a card).
- `components/CardSlot.tsx` — renders the new Shasta card kinds.

New Shasta-specific cards (`components/cards/`):
- `FindingsList.tsx` — list of findings with severity badge, title, framework chips (multi-framework — e.g., `SOC 2 · CC6.1`, `ISO 27001 · A.9.2`).
- `FindingDetail.tsx` — full finding with description, remediation snippet (truncated), affected resource, control mappings across frameworks, evidence count.
- `ComplianceScore.tsx` — single-framework score with trend arrow, severity breakdown ring, top affected services.
- `MultiFrameworkScore.tsx` — five vertical score columns (one per framework) with brand-gradient fill bars; greyed columns show "not enabled" for frameworks with no findings.
- `ControlSummary.tsx` — findings under a specific control with pass/fail counts and a list of failing resources.
- `RiskList.tsx` — open risks ranked by score, treatment column.
- `RiskDetail.tsx` — single risk with treatment plan, related finding, review history.

**File-count budget:** ~13 Python files + ~25 React files (mostly reused from VoiceApp).

### OpenAI Realtime session configuration

- **Model:** `gpt-realtime` (pinned in `realtime_config.py`)
- **Voice:** `cedar` or `marin` (A/B during build; pick before release)
- **Input audio format:** `pcm16` @ 24kHz
- **Turn detection:** `server_vad`, `threshold: 0.5`, `silence_duration_ms: 500`
- **Tools:** 14 tool schemas (see Tool Inventory below)
- **`input_audio_transcription`:** `{model: "whisper-1"}` so the user's spoken words appear in the transcript panel
- **System prompt:** ~250 words, includes Distiller rules + compliance-flavored persona + tool-use guidance + redirect rules for out-of-scope operations

## Tool Inventory

| # | Tool | Args | Returns | Card mounted |
|---|---|---|---|---|
| 1 | `list_findings` | `severity?`, `status?`, `domain?`, `cloud?`, `framework?`, `control_id?`, `limit?` | `Finding[]` | FindingsList |
| 2 | `get_finding` | `finding_id` | `FindingDetail` | FindingDetail |
| 3 | `list_top_blockers` | `limit?` (default 5) | `Finding[]` (highest-severity unresolved) | FindingsList |
| 4 | `get_resource_findings` | `resource_id` | `Finding[]` | FindingsList |
| 5 | `get_compliance_score` | `framework` ∈ {`soc2`, `iso27001`, `hipaa`, `iso42001`, `eu_ai_act`, `ai_governance`} | `ComplianceScore` | ComplianceScore |
| 6 | `get_multi_framework_score` | (no args) | `MultiFrameworkScore` | MultiFrameworkScore |
| 7 | `get_score_trend` | `framework`, `limit?` (default 10) | `ScoreTrend` | (no card — assistant speaks the delta) |
| 8 | `get_control_summary` | `framework`, `control_id?` | `ControlSummary[]` | ControlSummary |
| 9 | `list_scans` | `limit?` (default 10) | `Scan[]` | (no card) |
| 10 | `get_latest_scan` | (no args) | `ScanSummary` | (no card) |
| 11 | `list_risk_items` | `status?`, `level?` | `RiskItem[]` | RiskList |
| 12 | `get_risk_item` | `risk_id` | `RiskItem` | RiskDetail |
| 13 | `add_risk_item` | `title`, `description`, `category`, `likelihood`, `impact`, `treatment`, `treatment_plan?`, `related_finding?` | `ActionResult` | ActionToast |
| 14 | `update_risk` | `risk_id`, plus any of: `treatment`, `treatment_plan`, `status`, `review_notes` | `ActionResult` | ActionToast |

Tools 13 and 14 are the only writes. They map to single SQLite UPDATEs / INSERTs, complete in <50ms.

## The Distiller (system prompt)

```
You are Shasta's voice compliance assistant for the user's cloud security
posture. You are talking to a security engineer or founder over voice. Their
data is real — you have read access to their actual scan findings, compliance
scores across SOC 2 / ISO 27001 / HIPAA / ISO 42001 / EU AI Act, and risk
register.

VOICE OUTPUT RULES (non-negotiable):
- Maximum 25 words per response unless the user explicitly asks for detail.
- Lead with the most important fact. Numbers before context. Severity before
  description. Failed counts before passing counts.
- Never read JSON, ARNs, IP addresses, or long control IDs out loud unless
  the user asks.
- If listing items, name at most 3. Offer to continue ("...and 5 more — want
  the full list?").
- Use plain words, not compliance jargon, unless the user uses jargon first.
  (e.g., say "your encryption findings" not "your CC6.7 controls" unless
  the user asked about CC6.7.)

TOOL USE:
- For any question about findings, scores, controls, scans, or risks, call
  a tool. Never invent data.
- For ambiguous questions ("show me the critical ones"), make the most
  reasonable assumption (default: status=fail, scope=latest scan) and proceed;
  mention your assumption briefly.
- After an action tool succeeds (add_risk_item, update_risk), confirm in one
  short sentence.
- If a tool returns "no_data" or an empty list, say so honestly. Do not
  invent findings.

REDIRECTS (out of scope for voice — Shasta runs these via Claude Code skills):
- If the user asks to RUN A SCAN: "That's a heavier operation — run `/scan`
  in Claude Code. Want me to summarize what it'll do first?"
- If the user asks to GENERATE A REPORT/PDF: "Reports go to disk — run
  `/report` to generate one. I can summarize the latest scan first if that
  helps."
- If the user asks to GENERATE TERRAFORM / REMEDIATION CODE: "Run `/remediate`
  for the Terraform — voice can't deliver code cleanly. I can describe what
  the fix does."
- If the user asks to GENERATE POLICY DOCUMENTS: "Run `/policy-gen` for the
  policy docs."

PERSONA:
- Calm, precise, slightly understated. Think experienced compliance engineer
  on a Tuesday afternoon, not breaking-news anchor.
- Comfortable with both technical and founder audiences — adjust register to
  the question.
- Never apologize for tool latency. Never say "let me check that for you" —
  just do it.
```

## Data Flow (one turn, end-to-end)

User says *"What's failing in my latest scan?"*

1. Browser mic captures audio → WebRTC track to OpenAI
2. Server VAD detects `speech_started` → app shows "listening" state
3. Server VAD detects `speech_stopped` → model begins reasoning
4. Model decides to call `list_findings(status="fail", limit=20)`
5. `tool_call` event arrives at browser via data channel
6. Browser POSTs to `/tools/list_findings` with args
7. FastAPI calls `shasta.voice.store.list_findings(...)` → which calls `ShastaDB.get_latest_scan()`, filters findings, enriches with framework mappings via existing `mapper`/`iso27001_mapper`/`hipaa_mapper`, returns
8. Browser sends `function_call_output` back to OpenAI
9. In parallel: browser dispatches event → `<FindingsList>` animates in
10. OpenAI generates audio response (~"You have 12 failing checks. The most urgent is the public S3 bucket policy on prod-customer-data...")
11. Browser plays audio incrementally; transcript text appears in sync
12. Total time: target <1s p50 from `speech_stopped` to first audio byte

Barge-in works the same way as VoiceApp: VAD detects user speech mid-response, OpenAI cancels, browser stops playback, restart from step 2.

## CLI Integration

Invocation matches the existing `shasta.dashboard` pattern (`python -m shasta.dashboard`). No new entry-point in `pyproject.toml` — keeps Shasta's invocation conventions consistent.

```bash
$ python -m shasta.voice
✓ OPENAI_API_KEY found
✓ data/shasta.db exists (last scan: 2026-05-04 03:14, 34 findings)
→ Starting voice console at http://localhost:8090
→ Opening browser…
[uvicorn output]
```

Failure modes:

```bash
$ python -m shasta.voice
✗ OPENAI_API_KEY not set in environment
  Add to your shell: export OPENAI_API_KEY=sk-...
  Or to .env: echo 'OPENAI_API_KEY=sk-...' >> .env

$ python -m shasta.voice
✗ No scan data in data/shasta.db
  Run a scan first: open Claude Code and use /scan
```

Flags:
- `--port 8090` (default)
- `--no-open` (don't auto-launch browser)
- `--db data/shasta.db` (override DB path)
- `--host 127.0.0.1` (default; do NOT bind to 0.0.0.0 by default — voice has no auth)

## UI

Visual language is **identical to VoiceApp** (dark Transilience theme, Roboto, brand purple→magenta gradient, severity colors mapped to gradient stops). Layout is the same: header at top with logo + connection state; main area split into card slot (left, 70%) and live transcript (right, 30%); mic chrome at the bottom.

Header is **text-only** (per design decision): no logo asset. Just **"Shasta — Voice Console"** rendered in Roboto Bold against the dark background, with the connection-state indicator dot to the right. Removes one asset to ship and keeps the header lightweight.

Two notable visual additions vs VoiceApp:

- **Framework chips on FindingsList items.** Each finding gets small colored chips for the frameworks it maps to (`SOC 2 · CC6.1`, `ISO 27001 · A.9.2`, `HIPAA · §164.312(a)`). Helps the user see compliance overlap at a glance.
- **MultiFrameworkScore card.** Five vertical "score columns" (one per framework), each showing the headline percentage with the brand gradient as a vertical fill bar. Greyed columns for frameworks with no findings (e.g., user hasn't enabled HIPAA). Most visually striking card — anchors the *"how am I doing across the board?"* question.

## Error & Empty-State Handling

| State | Behavior |
|---|---|
| No scan data in DB | CLI refuses to start. Server never runs. |
| User asks about something with no matches | Tool returns `{"error": "no_data", "message": "..."}`. Model says *"I don't see any of those — want me to broaden the search?"* |
| User asks about an enabled framework with zero findings | Tool returns the score (likely 100%) with empty findings list. Model says *"You're clean on HIPAA — no findings."* |
| User asks about AI governance but no AI services in last scan | Tool returns `{"score": null, "reason": "no_ai_services_detected"}`. Model says *"I don't see any AI services in your last scan — that framework isn't applicable."* |
| Tool endpoint 500 | Returns `{"error": "tool_unavailable"}` to the model; model apologizes briefly. Logged with full traceback server-side. |
| User asks for an out-of-scope action (run scan, gen report) | System prompt instructs model to redirect with the appropriate slash-command. |
| OpenAI session drops mid-conversation | Reconnect once, surface failure on second attempt. |

All errors logged via `observability.log_tool_call(error=...)`. No silent failures.

## Testing

Different from VoiceApp because there's no mock layer to stub:

1. **Test SQLite fixture** (`tests/voice/conftest.py`) — pytest fixture creates a fresh SQLite at `tmp_path`, seeds it with a curated `Scan + Findings + RiskItems` payload that exercises every code path. ~150 lines of seed data crafted to support every tool's behavior. The seed data includes findings across multiple frameworks, multiple severities, multiple cloud providers, multiple statuses, plus risk items in various states.
2. **Tool function tests** (`tests/voice/test_tools_*.py`) — one test file per tool module (~5 files), targeting ≥85% line coverage of `src/shasta/voice/tools/`.
3. **Tool endpoint integration tests** (`tests/voice/test_tool_endpoints.py`) — FastAPI TestClient against the test SQLite, hitting every `/tools/*` endpoint with realistic args.
4. **Store facade tests** (`tests/voice/test_store.py`) — verify the facade composes `ShastaDB` + scoring/mapper functions correctly. Catches breakage if Shasta's internal APIs change.
5. **Session token endpoint test** (`tests/voice/test_session.py`) — mocks `httpx.post` to OpenAI, asserts payload shape and error handling.
6. **CLI test** (`tests/voice/test_cli.py`) — verifies the failure-mode messages (missing key, missing DB) and that `python -m shasta.voice --help` runs.
7. **No frontend unit tests** (per VoiceApp precedent — manual rehearsal covers UI).
8. **Manual end-to-end verification** — user runs a real `shasta scan` then `shasta voice`, exercises each major query, confirms cards mount correctly. Documented in the voice section of the Shasta README.

We do NOT add tests to Shasta's existing test suite for behaviors that already have coverage there (scoring logic, ShastaDB queries). We only test voice-specific code.

## Distribution / Install

Add to Shasta's `pyproject.toml`:

```toml
[project.optional-dependencies]
voice = [
    "fastapi>=0.115",
    "uvicorn[standard]>=0.32",
    "httpx>=0.27",
]
```

Pre-built React bundle committed at `src/shasta/voice/web/dist/`. Add to `.gitattributes`:

```
src/shasta/voice/web/dist/** linguist-generated=true
```

So GitHub doesn't pollute language stats with the bundle.

CI workflow (`.github/workflows/voice-bundle.yml`) rebuilds `web/dist/` on PRs that touch `web/src/` and fails if the committed bundle is out of date.

Package data declaration so `web/dist/**` ships with the wheel:

```toml
[tool.setuptools.package-data]
"shasta.voice" = ["web/dist/**/*"]
```

No `[project.scripts]` entry needed — invocation is `python -m shasta.voice` via the module's `__main__.py` (matches the existing `shasta.dashboard` pattern).

Update Shasta's root README (`README.md`) to mention voice as an optional capability:

> **Voice console (optional).** `pip install shasta[voice]` adds a voice-driven dashboard. After running a scan via Claude Code's `/scan` skill: `python -m shasta.voice` opens a browser at localhost:8090 — talk to your compliance posture. Requires `OPENAI_API_KEY`. Demo: a 60-second screen recording will be added once the prototype is rehearsed and recorded.

## Success Criteria

- `python -m shasta.voice` starts cleanly given a valid scan DB and `OPENAI_API_KEY`.
- All 14 tools work end-to-end against a real scan: read tools return correct data, write tools persist correctly to SQLite.
- Time from `speech_stopped` → first audio byte: <1s p50, <1.5s p95.
- Zero hallucinated data — every finding/score/risk the model mentions is traceable to the user's actual SQLite.
- Voice responses ≤25 words target, ≤30 words at p95.
- Barge-in works: user interrupts mid-sentence, assistant stops within 200ms.
- Tool layer test suite: ≥85% line coverage of `src/shasta/voice/tools/` and `src/shasta/voice/store.py`.
- The line *"to make this multi-tenant: add JWT middleware to `app.py` and bind user identity in `session.py`"* must be defensibly true on inspection.

## Cost envelope

- OpenAI Realtime: ~$0.06/min input, ~$0.24/min output. Build + ~5 rehearsals + light user testing: ~90 minutes of voice. Realistic budget: **$20–40** in OpenAI charges across the project. Hard cap: kill if it exceeds $75.
- No other paid services.
- Users running ShastaVoice pay for their own OpenAI usage. Document the per-minute cost in the voice section of the README so users can budget.

## Out of scope (deliberately)

- Demo / seeded fake data
- Multi-user sessions, accounts, JWT auth
- Long-running operation triggering over voice (scans, reports, remediation, policy gen)
- Mobile / responsive layout
- Hosted version of voice (e.g., voice.shasta.dev) — out of scope for this MVP
- Custom voice cloning
- Cost monitoring / per-tenant rate limiting (defer to hosted scenario)
- Internationalization
- Replay / save conversation history
- Voice-driven Whitney scans
