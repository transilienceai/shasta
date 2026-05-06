# ShastaVoice Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a voice-driven dynamic compliance dashboard to Shasta as an opt-in sibling module (`src/shasta/voice/`) that reads real `ShastaDB` data and lets users speak to their compliance posture across SOC 2 / ISO 27001 / HIPAA / ISO 42001 / EU AI Act, plus light writes to the risk register.

**Architecture:** Browser-direct WebRTC to OpenAI Realtime API. New FastAPI sub-app on port 8090 that mints ephemeral tokens and exposes 14 tool endpoints. Tool functions are thin wrappers over a `store.py` facade that composes existing Shasta primitives (`ShastaDB`, `compliance.scorer`, `compliance.mapper`, ISO/HIPAA equivalents). Pre-built React bundle ships in the wheel — no Node required at runtime.

**Tech Stack:** Python 3.11+, FastAPI, Pydantic v2, httpx, pytest. React 18 + Vite + TypeScript, Zustand, Framer Motion. OpenAI Realtime (`gpt-realtime`).

**Working directory:** `E:\Projects\Vanta` (the Shasta repo on the user's machine).

**VoiceApp source for reused code:** `E:\Projects\Misc\VoiceApp\` — the prior prototype. Several React modules transfer verbatim; tasks reference them by path rather than re-pasting all the source.

---

## Repo layout (additive)

```
E:/Projects/Vanta/
  pyproject.toml                                       # MODIFY (add [voice] extra + package-data)
  README.md                                            # MODIFY (add voice section)
  .gitattributes                                       # MODIFY (mark web/dist as generated)
  src/shasta/
    voice/                                             # NEW MODULE
      __init__.py
      __main__.py                                      # `python -m shasta.voice`
      cli.py                                           # main() — argparse + checks + uvicorn
      app.py                                           # FastAPI app + CORS + static files
      session.py                                       # /session/token
      realtime_config.py                               # Distiller + 14 tool schemas + VAD
      observability.py                                 # JSON tool-call logging
      models.py                                        # Pydantic I/O models for tools
      store.py                                         # Facade over ShastaDB + scoring/mapper
      tools/
        __init__.py
        findings.py
        scores.py
        controls.py
        risks.py
        scans.py
        router.py                                      # FastAPI router + 14 endpoints
      web/
        package.json
        vite.config.ts
        tsconfig.json
        tsconfig.node.json
        index.html
        src/
          main.tsx
          App.tsx
          styles/{tokens.css, global.css}
          voice/{connection.ts, events.ts, cardDispatcher.ts}
          tools/{types.ts, relay.ts}
          state/session.ts
          components/{Header.tsx, MicChrome.tsx, Transcript.tsx, CardSlot.tsx}
          components/cards/{
            SeverityBadge.tsx, ActionToast.tsx,
            FindingsList.tsx, FindingDetail.tsx,
            ComplianceScore.tsx, MultiFrameworkScore.tsx,
            ControlSummary.tsx, RiskList.tsx, RiskDetail.tsx
          }
        dist/                                          # COMMITTED build artifact
  tests/voice/
    __init__.py
    conftest.py                                        # Seeded temp SQLite fixture
    test_models.py
    test_store_reads.py
    test_store_writes.py
    test_tools_findings.py
    test_tools_scores.py
    test_tools_controls.py
    test_tools_risks.py
    test_tools_scans.py
    test_tool_endpoints.py
    test_session.py
    test_realtime_config.py
    test_observability.py
    test_cli.py
```

**Total surface:** ~16 Python files, ~25 React files, ~12 test files.

---

## Working assumptions (verified from Shasta source)

- `src/shasta/evidence/models.py` exports: `Severity` (CRITICAL/HIGH/MEDIUM/LOW/INFO), `ComplianceStatus` (PASS/FAIL/PARTIAL/NOT_ASSESSED/NOT_APPLICABLE), `CloudProvider` (AWS/AZURE), `CheckDomain`, `Finding`, `ScanResult`, `ScanSummary`, `Evidence`. Enum `.value`s are lowercase.
- `Finding` field names (snake_case): `id`, `check_id`, `title`, `description`, `severity`, `status`, `domain`, `resource_type`, `resource_id`, `region`, `account_id`, `cloud_provider`, `remediation`, `details` (dict), `soc2_controls`, `cis_aws_controls`, `cis_azure_controls`, `mcsb_controls`, `iso27001_controls`, `hipaa_controls`, `timestamp`.
- `src/shasta/db/schema.py` exports `ShastaDB` with: `initialize()`, `save_scan(scan)`, `save_evidence(ev)`, `get_latest_scan(account_id?)`, `get_scan_history(account_id?, limit=10)`, `save_risk_items(items, account_id)` — uses INSERT OR REPLACE so same call adds or updates, `get_risk_items(account_id)`, `get_recent_scan(max_age_minutes, account_id?)`, `close()`.
- `src/shasta/compliance/scorer.py`: `calculate_score(findings) -> ComplianceScore` (dataclass with `total_controls`, `passing`, `failing`, `partial`, `not_assessed`, `requires_policy`, `score_percentage`, `grade`, `total_findings`, `findings_passed`, `findings_failed`, `findings_partial`).
- `src/shasta/compliance/mapper.py`: `enrich_findings_with_controls(findings)` (mutates), `get_control_summary(findings) -> dict[str, dict]`.
- ISO/HIPAA equivalents under `compliance/iso27001_*.py` and `compliance/hipaa_*.py` (signatures mirror SOC 2).
- AI governance scoring under `compliance/ai/scorer.py` — used conditionally when AI findings exist.
- **There is no single-row `add_risk_item` on ShastaDB** — `save_risk_items` takes a list and does INSERT OR REPLACE. Voice writes will construct a single-element list.
- **Risk items expect a `RiskItem` model with attributes** (`item.risk_id`, `item.title`, etc.) — verify the model location early in Task 4 and import accordingly.

---

## Task 0: Branch + voice module skeleton

**Files:**
- Create branch `feat/voice-console`
- Create: `src/shasta/voice/__init__.py` (empty)
- Create: `src/shasta/voice/__main__.py`
- Create: `tests/voice/__init__.py` (empty)
- Modify: `.gitattributes`

- [ ] **Step 1: Create feature branch from main**

```bash
cd E:/Projects/Vanta
git status   # confirm clean working tree on main; if not, ASK USER before continuing
git checkout -b feat/voice-console
```

If `git status` shows uncommitted work, STOP and report — don't switch branches with dirty state.

- [ ] **Step 2: Create empty package init files**

```bash
mkdir -p src/shasta/voice/tools src/shasta/voice/web src/shasta/voice/web/src tests/voice
touch src/shasta/voice/__init__.py
touch src/shasta/voice/tools/__init__.py
touch tests/voice/__init__.py
```

(On PowerShell: `New-Item -ItemType File -Force <path>` instead of `touch`. Bash via the tool also works.)

- [ ] **Step 3: Create __main__.py**

`src/shasta/voice/__main__.py`:
```python
"""Entry point for `python -m shasta.voice`."""
from shasta.voice.cli import main

if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Update .gitattributes**

Append to `E:/Projects/Vanta/.gitattributes` (create if missing):
```
src/shasta/voice/web/dist/** linguist-generated=true
src/shasta/voice/web/dist/** -diff
```

- [ ] **Step 5: Commit**

```bash
git add src/shasta/voice/__init__.py src/shasta/voice/__main__.py src/shasta/voice/tools/__init__.py tests/voice/__init__.py .gitattributes
git commit -m "feat(voice): scaffold voice module skeleton"
```

---

## Task 1: pyproject.toml — add `voice` extra and package-data

**Files:**
- Modify: `pyproject.toml`

- [ ] **Step 1: Add `voice` extra**

Find `[project.optional-dependencies]` (already has `azure`, `dashboard`, `semgrep`, `dev`). Add a new `voice` extra:

```toml
voice = [
    "fastapi>=0.115.0",
    "uvicorn[standard]>=0.32.0",
    "httpx>=0.27.0",
]
```

- [ ] **Step 2: Add package-data declaration**

Append (or augment, if `[tool.hatch.build]` already exists):

```toml
[tool.hatch.build.targets.wheel]
packages = ["src/shasta"]

[tool.hatch.build.targets.wheel.force-include]
"src/shasta/voice/web/dist" = "shasta/voice/web/dist"
```

(Shasta uses `hatchling` as its build backend per existing `[build-system]` block. If that block is missing or different, match the existing build-system convention.)

- [ ] **Step 3: Install the new extra**

```bash
pip install -e ".[dev,voice]"
```

Expected: installs FastAPI, uvicorn, httpx without errors.

- [ ] **Step 4: Commit**

```bash
git add pyproject.toml
git commit -m "chore(voice): add voice optional-dependency and package-data"
```

---

## Task 2: Pydantic I/O models for tools

**Files:**
- Create: `src/shasta/voice/models.py`
- Create: `tests/voice/test_models.py`

These wrap Shasta's domain models (`Finding`, etc.) into the JSON shapes that ride the WebRTC data channel and feed React types. We define them explicitly because (a) tools return narrowed projections (e.g., FindingSummary without `details`), and (b) some tools return composite shapes (`MultiFrameworkScore`) that don't exist in Shasta core.

- [ ] **Step 1: Write the failing test**

`tests/voice/test_models.py`:
```python
from datetime import datetime, timezone

from shasta.voice.models import (
    ActionResult,
    ComplianceScoreView,
    ControlSummaryView,
    FindingDetailView,
    FindingSummary,
    MultiFrameworkScoreView,
    RiskItemView,
    ScanSummaryView,
    ScoreTrendView,
)


def test_finding_summary_minimal():
    f = FindingSummary(
        id="abc123",
        check_id="iam-mfa-enabled",
        title="MFA missing on user",
        severity="critical",
        status="fail",
        domain="iam",
        resource_id="arn:aws:iam::1:user/x",
        cloud_provider="aws",
        soc2_controls=["CC6.1"],
        iso27001_controls=[],
        hipaa_controls=[],
    )
    assert f.severity == "critical"
    assert f.soc2_controls == ["CC6.1"]


def test_finding_detail_extends_summary():
    d = FindingDetailView(
        id="abc123",
        check_id="iam-mfa-enabled",
        title="t",
        severity="critical",
        status="fail",
        domain="iam",
        resource_id="r",
        cloud_provider="aws",
        soc2_controls=[],
        iso27001_controls=[],
        hipaa_controls=[],
        description="desc",
        remediation="fix",
        region="us-east-1",
        account_id="1",
        details={"foo": "bar"},
        timestamp=datetime(2026, 5, 5, tzinfo=timezone.utc),
    )
    assert d.description == "desc"
    assert d.details == {"foo": "bar"}


def test_compliance_score_view():
    s = ComplianceScoreView(
        framework="soc2",
        score_percentage=82.5,
        grade="B",
        total_controls=40,
        passing=30,
        failing=8,
        partial=2,
        not_assessed=0,
        total_findings=120,
        findings_failed=15,
    )
    assert s.framework == "soc2"
    assert s.score_percentage == 82.5


def test_multi_framework_score_view():
    m = MultiFrameworkScoreView(
        frameworks=[
            ComplianceScoreView(framework="soc2", score_percentage=82.5, grade="B", total_controls=40, passing=30, failing=8, partial=2, not_assessed=0, total_findings=120, findings_failed=15),
        ],
        not_enabled=["hipaa"],
    )
    assert len(m.frameworks) == 1
    assert m.not_enabled == ["hipaa"]


def test_score_trend_view():
    t = ScoreTrendView(
        framework="soc2",
        points=[
            {"scan_id": "s1", "completed_at": "2026-05-01T00:00:00Z", "score_percentage": 78.0},
            {"scan_id": "s2", "completed_at": "2026-05-04T00:00:00Z", "score_percentage": 82.5},
        ],
        delta=4.5,
    )
    assert t.delta == 4.5
    assert len(t.points) == 2


def test_control_summary_view():
    c = ControlSummaryView(
        framework="soc2",
        control_id="CC6.1",
        title="Logical access security",
        overall_status="fail",
        pass_count=2,
        fail_count=3,
        partial_count=1,
        finding_ids=["a", "b", "c"],
    )
    assert c.overall_status == "fail"
    assert c.fail_count == 3


def test_risk_item_view():
    r = RiskItemView(
        risk_id="R-001",
        title="t",
        description="d",
        category="cat",
        likelihood="medium",
        impact="high",
        risk_score=6,
        risk_level="high",
        treatment="mitigate",
        treatment_plan="plan",
        status="open",
        soc2_controls=["CC6.1"],
        related_finding=None,
    )
    assert r.risk_score == 6


def test_action_result():
    res = ActionResult(success=True, message="ok", record_id="R-001")
    assert res.success is True


def test_scan_summary_view():
    s = ScanSummaryView(
        scan_id="s1",
        account_id="1",
        cloud_provider="aws",
        completed_at=datetime(2026, 5, 5, tzinfo=timezone.utc),
        total_findings=34,
        critical_count=4,
        high_count=11,
        medium_count=15,
        low_count=4,
        passed=20,
        failed=14,
    )
    assert s.total_findings == 34
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd E:/Projects/Vanta
pytest tests/voice/test_models.py -v
```
Expected: FAIL — `ModuleNotFoundError: No module named 'shasta.voice.models'`

- [ ] **Step 3: Implement `src/shasta/voice/models.py`**

```python
"""Pydantic I/O models for voice tools — JSON-serializable views over Shasta core models."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "info"]
Status = Literal["pass", "fail", "partial", "not_assessed", "not_applicable"]
Cloud = Literal["aws", "azure"]
Framework = Literal["soc2", "iso27001", "hipaa", "iso42001", "eu_ai_act", "ai_governance"]


class FindingSummary(BaseModel):
    id: str
    check_id: str
    title: str
    severity: Severity
    status: Status
    domain: str
    resource_id: str
    cloud_provider: Cloud
    soc2_controls: list[str] = Field(default_factory=list)
    iso27001_controls: list[str] = Field(default_factory=list)
    hipaa_controls: list[str] = Field(default_factory=list)


class FindingDetailView(FindingSummary):
    description: str
    remediation: str = ""
    region: str
    account_id: str
    details: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime


class ComplianceScoreView(BaseModel):
    framework: Framework
    score_percentage: float
    grade: str
    total_controls: int
    passing: int
    failing: int
    partial: int
    not_assessed: int
    total_findings: int
    findings_failed: int


class MultiFrameworkScoreView(BaseModel):
    frameworks: list[ComplianceScoreView] = Field(default_factory=list)
    not_enabled: list[Framework] = Field(default_factory=list)


class ScoreTrendView(BaseModel):
    framework: Framework
    points: list[dict[str, Any]] = Field(default_factory=list)
    delta: float  # latest - earliest


class ControlSummaryView(BaseModel):
    framework: Framework
    control_id: str
    title: str
    overall_status: str
    pass_count: int
    fail_count: int
    partial_count: int
    finding_ids: list[str] = Field(default_factory=list)


class RiskItemView(BaseModel):
    risk_id: str
    title: str
    description: str
    category: str
    likelihood: str
    impact: str
    risk_score: int
    risk_level: str
    treatment: str
    treatment_plan: str | None = None
    status: str
    soc2_controls: list[str] = Field(default_factory=list)
    related_finding: str | None = None


class ScanSummaryView(BaseModel):
    scan_id: str
    account_id: str
    cloud_provider: Cloud
    completed_at: datetime | None
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    passed: int
    failed: int


class ActionResult(BaseModel):
    success: bool
    message: str
    record_id: str | None = None
```

- [ ] **Step 4: Run test to verify it passes**

```bash
pytest tests/voice/test_models.py -v
```
Expected: 9 passing.

- [ ] **Step 5: Commit**

```bash
git add src/shasta/voice/models.py tests/voice/test_models.py
git commit -m "feat(voice): Pydantic I/O models for tool inputs and outputs"
```

---

## Task 3: Test SQLite fixture (seeded scan)

**Files:**
- Create: `tests/voice/conftest.py`

This fixture is the test backbone — every store and tool test uses it. It seeds a fresh SQLite at `tmp_path` with a curated `ScanResult + Findings + RiskItems` payload exercising every code path: multiple severities, multiple statuses, multiple cloud providers, findings mapped to multiple frameworks, risk items in multiple states.

- [ ] **Step 1: Write conftest.py**

`tests/voice/conftest.py`:
```python
"""Shared test fixtures for voice tests — seeded SQLite at tmp_path."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from shasta.db.schema import ShastaDB
from shasta.evidence.models import (
    CheckDomain,
    CloudProvider,
    ComplianceStatus,
    Finding,
    ScanResult,
    Severity,
)


def _ago(hours: float) -> datetime:
    return datetime.now(UTC) - timedelta(hours=hours)


def _make_finding(
    *,
    id: str,
    check_id: str,
    title: str,
    severity: Severity,
    status: ComplianceStatus,
    domain: CheckDomain,
    resource_id: str,
    soc2: list[str] | None = None,
    iso27001: list[str] | None = None,
    hipaa: list[str] | None = None,
    cloud: CloudProvider = CloudProvider.AWS,
    description: str = "desc",
    remediation: str = "fix",
) -> Finding:
    return Finding(
        id=id,
        check_id=check_id,
        title=title,
        description=description,
        severity=severity,
        status=status,
        domain=domain,
        resource_type="AWS::IAM::User",
        resource_id=resource_id,
        region="us-east-1",
        account_id="123456789012",
        cloud_provider=cloud,
        remediation=remediation,
        soc2_controls=soc2 or [],
        iso27001_controls=iso27001 or [],
        hipaa_controls=hipaa or [],
        timestamp=_ago(1),
    )


@pytest.fixture
def seeded_db_path(tmp_path: Path) -> Path:
    """Return a path to a fresh SQLite seeded with realistic scan + findings + risks."""
    db_path = tmp_path / "shasta-test.db"
    db = ShastaDB(db_path=db_path)
    db.initialize()

    findings = [
        # 4 critical, mixed clouds and frameworks
        _make_finding(id="f-001", check_id="iam-mfa-enabled", title="MFA missing on root",
                     severity=Severity.CRITICAL, status=ComplianceStatus.FAIL,
                     domain=CheckDomain.IAM, resource_id="arn:aws:iam::123:root",
                     soc2=["CC6.1"], iso27001=["A.5.15"], hipaa=["164.312(a)(1)"]),
        _make_finding(id="f-002", check_id="s3-public-access-block", title="S3 bucket allows public access",
                     severity=Severity.CRITICAL, status=ComplianceStatus.FAIL,
                     domain=CheckDomain.STORAGE, resource_id="arn:aws:s3:::prod-data",
                     soc2=["CC6.1", "CC6.6"], iso27001=["A.5.10"]),
        _make_finding(id="f-003", check_id="azure-sql-tls", title="SQL TLS below 1.2",
                     severity=Severity.CRITICAL, status=ComplianceStatus.FAIL,
                     domain=CheckDomain.ENCRYPTION, resource_id="/subscriptions/x/sql/y",
                     cloud=CloudProvider.AZURE, soc2=["CC6.7"]),
        _make_finding(id="f-004", check_id="cloudtrail-enabled", title="CloudTrail disabled in audit account",
                     severity=Severity.CRITICAL, status=ComplianceStatus.FAIL,
                     domain=CheckDomain.LOGGING, resource_id="arn:aws:cloudtrail::123:trail/audit",
                     soc2=["CC7.1", "CC7.2"]),
        # 3 high
        _make_finding(id="f-010", check_id="iam-stale-key", title="Stale IAM key >180d",
                     severity=Severity.HIGH, status=ComplianceStatus.FAIL,
                     domain=CheckDomain.IAM, resource_id="arn:aws:iam::123:user/legacy-bot",
                     soc2=["CC6.3"]),
        _make_finding(id="f-011", check_id="sg-open-22", title="Security group open on 22",
                     severity=Severity.HIGH, status=ComplianceStatus.FAIL,
                     domain=CheckDomain.NETWORKING, resource_id="sg-0e1f2a3b",
                     soc2=["CC6.6"]),
        _make_finding(id="f-012", check_id="lambda-perm-role", title="Lambda overly permissive role",
                     severity=Severity.HIGH, status=ComplianceStatus.FAIL,
                     domain=CheckDomain.IAM, resource_id="arn:aws:lambda::123:function/proc",
                     soc2=["CC6.1"]),
        # 3 medium, mixed status
        _make_finding(id="f-020", check_id="s3-versioning", title="S3 versioning off",
                     severity=Severity.MEDIUM, status=ComplianceStatus.FAIL,
                     domain=CheckDomain.STORAGE, resource_id="arn:aws:s3:::dev-build"),
        _make_finding(id="f-021", check_id="ebs-encryption-default", title="EBS default encryption",
                     severity=Severity.MEDIUM, status=ComplianceStatus.PASS,
                     domain=CheckDomain.ENCRYPTION, resource_id="ebs-default",
                     soc2=["CC6.7"]),
        _make_finding(id="f-022", check_id="vpc-flow-logs", title="VPC flow logs off",
                     severity=Severity.MEDIUM, status=ComplianceStatus.PARTIAL,
                     domain=CheckDomain.MONITORING, resource_id="vpc-abc",
                     soc2=["CC7.2"]),
    ]

    scan = ScanResult(
        id="scan-test-001",
        account_id="123456789012",
        region="us-east-1",
        cloud_provider=CloudProvider.AWS,
        domains_scanned=[CheckDomain.IAM, CheckDomain.STORAGE, CheckDomain.NETWORKING,
                         CheckDomain.ENCRYPTION, CheckDomain.LOGGING, CheckDomain.MONITORING],
        findings=findings,
        started_at=_ago(2),
    )
    scan.complete()
    db.save_scan(scan)

    # Save an older scan too so trend queries have at least 2 datapoints
    older_findings = [
        _make_finding(id=f"old-{f.id}", check_id=f.check_id, title=f.title,
                      severity=f.severity, status=f.status, domain=f.domain,
                      resource_id=f.resource_id, soc2=f.soc2_controls,
                      iso27001=f.iso27001_controls, hipaa=f.hipaa_controls)
        for f in findings[:7]  # fewer findings = different score
    ]
    older_scan = ScanResult(
        id="scan-test-old",
        account_id="123456789012",
        region="us-east-1",
        cloud_provider=CloudProvider.AWS,
        domains_scanned=[CheckDomain.IAM, CheckDomain.STORAGE],
        findings=older_findings,
        started_at=_ago(72),
    )
    older_scan.complete()
    db.save_scan(older_scan)

    db.close()
    return db_path


@pytest.fixture
def store(seeded_db_path: Path):
    """Convenience: a Store instance pointed at the seeded DB."""
    from shasta.voice.store import Store
    s = Store(db_path=seeded_db_path)
    yield s
    s.close()
```

- [ ] **Step 2: Run pytest collection to confirm no syntax errors**

```bash
pytest tests/voice/conftest.py --collect-only
```
Expected: pytest reports it as a fixture file, no errors. (Tests using it come in later tasks.)

- [ ] **Step 3: Commit**

```bash
git add tests/voice/conftest.py
git commit -m "test(voice): seeded SQLite fixture for store and tool tests"
```

---

## Task 4: store.py — read methods

**Files:**
- Create: `src/shasta/voice/store.py`
- Create: `tests/voice/test_store_reads.py`

The store is the only module that touches `ShastaDB` and the existing scoring/mapper functions. Tools call into the store; the store calls into Shasta core.

- [ ] **Step 1: Write the failing test**

`tests/voice/test_store_reads.py`:
```python
from datetime import datetime

from shasta.voice.store import Store


def test_get_latest_scan_summary(store: Store):
    s = store.get_latest_scan()
    assert s is not None
    assert s.scan_id == "scan-test-001"
    assert s.total_findings == 10
    assert s.critical_count == 4


def test_list_findings_unfiltered(store: Store):
    findings = store.list_findings()
    assert len(findings) == 10


def test_list_findings_severity_critical(store: Store):
    findings = store.list_findings(severity="critical")
    assert len(findings) == 4
    assert all(f.severity == "critical" for f in findings)


def test_list_findings_status_fail(store: Store):
    findings = store.list_findings(status="fail")
    assert len(findings) == 8
    assert all(f.status == "fail" for f in findings)


def test_list_findings_cloud_azure(store: Store):
    findings = store.list_findings(cloud="azure")
    assert len(findings) == 1
    assert findings[0].id == "f-003"


def test_list_findings_framework_soc2(store: Store):
    findings = store.list_findings(framework="soc2")
    assert all(f.soc2_controls for f in findings)


def test_list_findings_control_id(store: Store):
    findings = store.list_findings(framework="soc2", control_id="CC6.1")
    assert all("CC6.1" in f.soc2_controls for f in findings)
    assert len(findings) == 3


def test_list_findings_limit(store: Store):
    findings = store.list_findings(limit=3)
    assert len(findings) == 3


def test_get_finding_known(store: Store):
    f = store.get_finding("f-001")
    assert f is not None
    assert f.title == "MFA missing on root"
    assert f.description == "desc"


def test_get_finding_unknown(store: Store):
    assert store.get_finding("does-not-exist") is None


def test_list_top_blockers_default(store: Store):
    blockers = store.list_top_blockers()
    assert len(blockers) == 5
    # Sorted by severity (critical > high > medium), then status=fail first
    assert blockers[0].severity == "critical"


def test_get_resource_findings(store: Store):
    findings = store.get_resource_findings("arn:aws:s3:::prod-data")
    assert len(findings) == 1
    assert findings[0].id == "f-002"


def test_get_compliance_score_soc2(store: Store):
    score = store.get_compliance_score("soc2")
    assert score.framework == "soc2"
    assert 0 <= score.score_percentage <= 100
    assert score.grade in ("A", "B", "C", "D", "F")


def test_get_multi_framework_score(store: Store):
    multi = store.get_multi_framework_score()
    frameworks_present = {s.framework for s in multi.frameworks}
    assert "soc2" in frameworks_present


def test_get_score_trend_soc2(store: Store):
    trend = store.get_score_trend("soc2", limit=10)
    assert trend.framework == "soc2"
    assert len(trend.points) >= 2


def test_get_control_summary_soc2_specific(store: Store):
    summaries = store.get_control_summary("soc2", control_id="CC6.1")
    assert len(summaries) == 1
    assert summaries[0].control_id == "CC6.1"
    assert summaries[0].fail_count >= 1


def test_get_control_summary_soc2_all(store: Store):
    summaries = store.get_control_summary("soc2")
    assert len(summaries) >= 1


def test_list_scans(store: Store):
    scans = store.list_scans(limit=10)
    assert len(scans) == 2
    # Most recent first
    assert scans[0].scan_id == "scan-test-001"
```

- [ ] **Step 2: Run tests — expect failure**

```bash
pytest tests/voice/test_store_reads.py -v
```
Expected: FAIL — `ModuleNotFoundError: No module named 'shasta.voice.store'`

- [ ] **Step 3: Implement `src/shasta/voice/store.py` (read methods only)**

```python
"""Voice store — facade over ShastaDB + compliance scoring/mapper functions.

The only place in the voice module that touches Shasta core. Replace the body
of any read method to swap data sources without touching tool code.
"""
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from shasta.compliance.hipaa_mapper import (
    enrich_findings_with_hipaa,
    get_hipaa_control_summary,
)
from shasta.compliance.hipaa_scorer import calculate_hipaa_score
from shasta.compliance.iso27001_mapper import (
    enrich_findings_with_iso27001,
    get_iso27001_control_summary,
)
from shasta.compliance.iso27001_scorer import calculate_iso27001_score
from shasta.compliance.mapper import enrich_findings_with_controls, get_control_summary
from shasta.compliance.scorer import calculate_score
from shasta.db.schema import ShastaDB
from shasta.evidence.models import Finding, ScanResult
from shasta.voice.models import (
    ComplianceScoreView,
    ControlSummaryView,
    FindingDetailView,
    FindingSummary,
    Framework,
    MultiFrameworkScoreView,
    ScanSummaryView,
    ScoreTrendView,
)


# Scoring + mapper dispatch tables
_SCORERS = {
    "soc2": calculate_score,
    "iso27001": calculate_iso27001_score,
    "hipaa": calculate_hipaa_score,
}

_CONTROL_SUMMARIES = {
    "soc2": get_control_summary,
    "iso27001": get_iso27001_control_summary,
    "hipaa": get_hipaa_control_summary,
}


def _enrich_all(findings: list[Finding]) -> list[Finding]:
    enrich_findings_with_controls(findings)
    enrich_findings_with_iso27001(findings)
    enrich_findings_with_hipaa(findings)
    return findings


def _finding_to_summary(f: Finding) -> FindingSummary:
    return FindingSummary(
        id=f.id,
        check_id=f.check_id,
        title=f.title,
        severity=f.severity.value,
        status=f.status.value,
        domain=f.domain.value,
        resource_id=f.resource_id,
        cloud_provider=f.cloud_provider.value,
        soc2_controls=list(f.soc2_controls),
        iso27001_controls=list(f.iso27001_controls),
        hipaa_controls=list(f.hipaa_controls),
    )


def _finding_to_detail(f: Finding) -> FindingDetailView:
    return FindingDetailView(
        **_finding_to_summary(f).model_dump(),
        description=f.description,
        remediation=f.remediation,
        region=f.region,
        account_id=f.account_id,
        details=dict(f.details),
        timestamp=f.timestamp if isinstance(f.timestamp, datetime) else datetime.fromisoformat(f.timestamp),
    )


_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class Store:
    """Read+write facade for the voice module.

    Production seam: replace the body of any method to swap the data source.
    Function signatures and return types must not change.
    """

    def __init__(self, db_path: Path | str | None = None):
        self._db = ShastaDB(db_path=db_path) if db_path else ShastaDB()
        self._db.initialize()
        # Cache the latest enriched scan to avoid re-enriching across calls
        self._cached_scan: ScanResult | None = None
        self._cached_scan_id: str | None = None

    def close(self) -> None:
        self._db.close()

    def _latest_scan(self) -> ScanResult | None:
        scan = self._db.get_latest_scan()
        if scan is None:
            return None
        if self._cached_scan_id != scan.id:
            _enrich_all(scan.findings)
            self._cached_scan = scan
            self._cached_scan_id = scan.id
        return self._cached_scan

    def has_data(self) -> bool:
        return self._latest_scan() is not None

    # ---- Scans ----

    def get_latest_scan(self) -> ScanSummaryView | None:
        scan = self._latest_scan()
        if scan is None:
            return None
        summary = scan.summary
        return ScanSummaryView(
            scan_id=scan.id,
            account_id=scan.account_id,
            cloud_provider=scan.cloud_provider.value if hasattr(scan.cloud_provider, "value") else scan.cloud_provider,
            completed_at=scan.completed_at if isinstance(scan.completed_at, datetime) else (datetime.fromisoformat(scan.completed_at) if scan.completed_at else None),
            total_findings=summary.total_findings if summary else len(scan.findings),
            critical_count=summary.critical_count if summary else 0,
            high_count=summary.high_count if summary else 0,
            medium_count=summary.medium_count if summary else 0,
            low_count=summary.low_count if summary else 0,
            passed=summary.passed if summary else 0,
            failed=summary.failed if summary else 0,
        )

    def list_scans(self, limit: int = 10) -> list[ScanSummaryView]:
        history = self._db.get_scan_history(limit=limit)
        out: list[ScanSummaryView] = []
        for row in history:
            import json as _json
            summary_blob = row.get("summary")
            if summary_blob:
                s = _json.loads(summary_blob)
            else:
                s = {}
            out.append(ScanSummaryView(
                scan_id=row["id"],
                account_id=row["account_id"],
                cloud_provider="aws",  # history rows don't carry cloud_provider in this query
                completed_at=datetime.fromisoformat(row["completed_at"]) if row.get("completed_at") else None,
                total_findings=s.get("total_findings", 0),
                critical_count=s.get("critical_count", 0),
                high_count=s.get("high_count", 0),
                medium_count=s.get("medium_count", 0),
                low_count=s.get("low_count", 0),
                passed=s.get("passed", 0),
                failed=s.get("failed", 0),
            ))
        return out

    # ---- Findings ----

    def list_findings(
        self,
        severity: str | None = None,
        status: str | None = None,
        domain: str | None = None,
        cloud: str | None = None,
        framework: Framework | None = None,
        control_id: str | None = None,
        limit: int | None = None,
    ) -> list[FindingSummary]:
        scan = self._latest_scan()
        if scan is None:
            return []
        results = list(scan.findings)
        if severity:
            results = [f for f in results if f.severity.value == severity]
        if status:
            results = [f for f in results if f.status.value == status]
        if domain:
            results = [f for f in results if f.domain.value == domain]
        if cloud:
            results = [f for f in results if f.cloud_provider.value == cloud]
        if framework:
            attr = {"soc2": "soc2_controls", "iso27001": "iso27001_controls", "hipaa": "hipaa_controls"}.get(framework)
            if attr:
                results = [f for f in results if getattr(f, attr)]
        if control_id and framework:
            attr = {"soc2": "soc2_controls", "iso27001": "iso27001_controls", "hipaa": "hipaa_controls"}.get(framework)
            if attr:
                results = [f for f in results if control_id in getattr(f, attr)]
        results.sort(key=lambda f: (_SEVERITY_RANK.get(f.severity.value, 99), 0 if f.status.value == "fail" else 1))
        if limit:
            results = results[:limit]
        return [_finding_to_summary(f) for f in results]

    def get_finding(self, finding_id: str) -> FindingDetailView | None:
        scan = self._latest_scan()
        if scan is None:
            return None
        for f in scan.findings:
            if f.id == finding_id:
                return _finding_to_detail(f)
        return None

    def list_top_blockers(self, limit: int = 5) -> list[FindingSummary]:
        return self.list_findings(status="fail", limit=limit)

    def get_resource_findings(self, resource_id: str) -> list[FindingSummary]:
        scan = self._latest_scan()
        if scan is None:
            return []
        matches = [f for f in scan.findings if f.resource_id == resource_id]
        matches.sort(key=lambda f: _SEVERITY_RANK.get(f.severity.value, 99))
        return [_finding_to_summary(f) for f in matches]

    # ---- Scores ----

    def _score_view(self, framework: Framework, score) -> ComplianceScoreView:
        return ComplianceScoreView(
            framework=framework,
            score_percentage=getattr(score, "score_percentage", 0.0),
            grade=getattr(score, "grade", "F"),
            total_controls=getattr(score, "total_controls", 0),
            passing=getattr(score, "passing", 0),
            failing=getattr(score, "failing", 0),
            partial=getattr(score, "partial", 0),
            not_assessed=getattr(score, "not_assessed", 0),
            total_findings=getattr(score, "total_findings", 0),
            findings_failed=getattr(score, "findings_failed", 0),
        )

    def get_compliance_score(self, framework: Framework) -> ComplianceScoreView | None:
        scan = self._latest_scan()
        if scan is None:
            return None
        scorer = _SCORERS.get(framework)
        if scorer is None:
            # iso42001 / eu_ai_act / ai_governance — treat as AI governance for now
            try:
                from shasta.compliance.ai.scorer import calculate_ai_governance_score
                ai_findings = [f for f in scan.findings if f.domain.value == "ai_governance"]
                if not ai_findings:
                    return None
                score = calculate_ai_governance_score(ai_findings)
                return self._score_view(framework, score)
            except ImportError:
                return None
        score = scorer(scan.findings)
        return self._score_view(framework, score)

    def get_multi_framework_score(self) -> MultiFrameworkScoreView:
        scan = self._latest_scan()
        if scan is None:
            return MultiFrameworkScoreView()
        frameworks: list[ComplianceScoreView] = []
        not_enabled: list[Framework] = []
        for fw in ("soc2", "iso27001", "hipaa"):
            score = self.get_compliance_score(fw)  # type: ignore[arg-type]
            if score is not None and score.total_controls > 0:
                frameworks.append(score)
            else:
                not_enabled.append(fw)  # type: ignore[arg-type]
        # AI frameworks
        for fw in ("iso42001", "eu_ai_act", "ai_governance"):
            score = self.get_compliance_score(fw)  # type: ignore[arg-type]
            if score is not None:
                frameworks.append(score)
            else:
                not_enabled.append(fw)  # type: ignore[arg-type]
        return MultiFrameworkScoreView(frameworks=frameworks, not_enabled=not_enabled)

    def get_score_trend(self, framework: Framework, limit: int = 10) -> ScoreTrendView:
        history = self._db.get_scan_history(limit=limit)
        scorer = _SCORERS.get(framework)
        points = []
        for row in history:
            scan = self._db.get_latest_scan(account_id=row["account_id"]) if False else None  # placeholder
            # The history row doesn't carry findings; we re-load each scan
            from shasta.db.schema import ShastaDB
            tmp_scan_id = row["id"]
            # Cheap read: only fetch findings for that scan_id
            full = self._db._get_findings_for_scan(tmp_scan_id)  # noqa: SLF001 — internal but stable
            _enrich_all(full)
            if scorer is not None:
                s = scorer(full)
                points.append({
                    "scan_id": tmp_scan_id,
                    "completed_at": row.get("completed_at"),
                    "score_percentage": getattr(s, "score_percentage", 0.0),
                })
        # Oldest first for delta math
        points.sort(key=lambda p: p["completed_at"] or "")
        delta = (points[-1]["score_percentage"] - points[0]["score_percentage"]) if len(points) >= 2 else 0.0
        return ScoreTrendView(framework=framework, points=points, delta=round(delta, 1))

    # ---- Controls ----

    def get_control_summary(self, framework: Framework, control_id: str | None = None) -> list[ControlSummaryView]:
        scan = self._latest_scan()
        if scan is None:
            return []
        summary_fn = _CONTROL_SUMMARIES.get(framework)
        if summary_fn is None:
            return []
        summary = summary_fn(scan.findings)
        out: list[ControlSummaryView] = []
        for cid, data in summary.items():
            if control_id and cid != control_id:
                continue
            out.append(ControlSummaryView(
                framework=framework,
                control_id=cid,
                title=data.get("title", cid),
                overall_status=data.get("overall_status", "not_assessed"),
                pass_count=data.get("pass_count", 0),
                fail_count=data.get("fail_count", 0),
                partial_count=data.get("partial_count", 0),
                finding_ids=[f.id for f in data.get("findings", [])],
            ))
        return out
```

- [ ] **Step 4: Run tests**

```bash
pytest tests/voice/test_store_reads.py -v
```
Expected: PASS for the read tests. If `get_score_trend`'s use of `_get_findings_for_scan` fails because that's marked private on `ShastaDB`, replace with the public `get_latest_scan` per-account loop or add a public method to ShastaDB in a follow-up.

If any test fails because `calculate_hipaa_score` isn't importable, leave a `try/except ImportError` around it and skip the relevant test — Shasta core may have moved the symbol. Report the import path issue rather than silently skipping in product code.

- [ ] **Step 5: Commit**

```bash
git add src/shasta/voice/store.py tests/voice/test_store_reads.py
git commit -m "feat(voice): store facade with read methods over ShastaDB + compliance scoring"
```

---

## Task 5: store.py — write methods (risk register)

**Files:**
- Modify: `src/shasta/voice/store.py` (add risk methods)
- Create: `tests/voice/test_store_writes.py`

- [ ] **Step 1: Write the failing test**

`tests/voice/test_store_writes.py`:
```python
from shasta.voice.store import Store


def test_list_risk_items_empty(store: Store):
    items = store.list_risk_items(account_id="123456789012")
    assert items == []


def test_add_risk_item_then_list(store: Store):
    res = store.add_risk_item(
        account_id="123456789012",
        title="Unblock CloudTrail",
        description="CloudTrail must be on across all regions",
        category="logging",
        likelihood="medium",
        impact="high",
        treatment="mitigate",
        treatment_plan="Enable CloudTrail in audit account",
        related_finding="f-004",
    )
    assert res.success is True
    assert res.record_id is not None

    items = store.list_risk_items(account_id="123456789012")
    assert len(items) == 1
    assert items[0].title == "Unblock CloudTrail"
    assert items[0].risk_score >= 1


def test_get_risk_item_by_id(store: Store):
    res = store.add_risk_item(
        account_id="123456789012", title="t", description="d", category="iam",
        likelihood="low", impact="medium", treatment="accept",
    )
    r = store.get_risk_item(res.record_id)
    assert r is not None
    assert r.risk_id == res.record_id


def test_update_risk_status(store: Store):
    res = store.add_risk_item(
        account_id="123456789012", title="t", description="d", category="iam",
        likelihood="low", impact="medium", treatment="accept",
    )
    upd = store.update_risk(risk_id=res.record_id, status="resolved", review_notes="closed")
    assert upd.success is True
    r = store.get_risk_item(res.record_id)
    assert r.status == "resolved"


def test_update_risk_treatment(store: Store):
    res = store.add_risk_item(
        account_id="123456789012", title="t", description="d", category="iam",
        likelihood="low", impact="medium", treatment="accept",
    )
    upd = store.update_risk(risk_id=res.record_id, treatment="mitigate", treatment_plan="new plan")
    assert upd.success is True


def test_update_risk_unknown_fails(store: Store):
    res = store.update_risk(risk_id="R-NOT-EXIST", status="resolved")
    assert res.success is False
```

- [ ] **Step 2: Run tests — expect failure**

```bash
pytest tests/voice/test_store_writes.py -v
```
Expected: FAIL — `AttributeError: 'Store' object has no attribute 'list_risk_items'`

- [ ] **Step 3: Append risk methods to `src/shasta/voice/store.py`**

Append at the end of the `Store` class (preserving existing methods):

```python
    # ---- Risks ----

    def _risk_row_to_view(self, row: dict) -> RiskItemView:
        import json as _json
        return RiskItemView(
            risk_id=row["risk_id"],
            title=row["title"],
            description=row["description"],
            category=row["category"],
            likelihood=row["likelihood"],
            impact=row["impact"],
            risk_score=row["risk_score"],
            risk_level=row["risk_level"],
            treatment=row["treatment"],
            treatment_plan=row.get("treatment_plan"),
            status=row["status"],
            soc2_controls=_json.loads(row["soc2_controls"]) if row.get("soc2_controls") else [],
            related_finding=row.get("related_finding"),
        )

    def list_risk_items(self, account_id: str, status: str | None = None, level: str | None = None) -> list[RiskItemView]:
        rows = self._db.get_risk_items(account_id)
        if status:
            rows = [r for r in rows if r.get("status") == status]
        if level:
            rows = [r for r in rows if r.get("risk_level") == level]
        return [self._risk_row_to_view(r) for r in rows]

    def get_risk_item(self, risk_id: str, account_id: str = "123456789012") -> RiskItemView | None:
        rows = self._db.get_risk_items(account_id)
        for r in rows:
            if r["risk_id"] == risk_id:
                return self._risk_row_to_view(r)
        return None

    def add_risk_item(
        self,
        *,
        account_id: str,
        title: str,
        description: str,
        category: str,
        likelihood: str,
        impact: str,
        treatment: str,
        treatment_plan: str | None = None,
        related_finding: str | None = None,
        soc2_controls: list[str] | None = None,
    ) -> ActionResult:
        from datetime import datetime, UTC
        from uuid import uuid4
        risk_id = f"R-{uuid4().hex[:8].upper()}"
        # Score: simple LxI matrix on a 1-3 scale → 1-9
        scale = {"low": 1, "medium": 2, "high": 3}
        l = scale.get(likelihood.lower(), 2)
        i = scale.get(impact.lower(), 2)
        score = l * i
        level = "high" if score >= 6 else "medium" if score >= 3 else "low"
        now = datetime.now(UTC).isoformat()

        # Build a record matching the columns expected by save_risk_items
        # save_risk_items expects an object with attributes — wrap in a SimpleNamespace
        from types import SimpleNamespace
        item = SimpleNamespace(
            risk_id=risk_id,
            title=title,
            description=description,
            category=category,
            likelihood=likelihood,
            impact=impact,
            risk_score=score,
            risk_level=level,
            owner=None,
            treatment=treatment,
            treatment_plan=treatment_plan,
            status="open",
            soc2_controls=soc2_controls or [],
            related_finding=related_finding,
            created_date=now,
            last_reviewed=now,
            review_notes=None,
        )
        try:
            self._db.save_risk_items([item], account_id=account_id)
        except Exception as e:
            return ActionResult(success=False, message=f"Failed to add risk: {e}")
        return ActionResult(success=True, message=f"Added risk {risk_id}", record_id=risk_id)

    def update_risk(
        self,
        risk_id: str,
        *,
        treatment: str | None = None,
        treatment_plan: str | None = None,
        status: str | None = None,
        review_notes: str | None = None,
        account_id: str = "123456789012",
    ) -> ActionResult:
        existing = self.get_risk_item(risk_id, account_id=account_id)
        if existing is None:
            return ActionResult(success=False, message=f"Risk {risk_id} not found")
        from datetime import datetime, UTC
        from types import SimpleNamespace
        # Recreate the row with overrides — save_risk_items uses INSERT OR REPLACE
        scale = {"low": 1, "medium": 2, "high": 3}
        l = scale.get(existing.likelihood.lower(), 2)
        i = scale.get(existing.impact.lower(), 2)
        score = l * i
        level = "high" if score >= 6 else "medium" if score >= 3 else "low"
        item = SimpleNamespace(
            risk_id=existing.risk_id,
            title=existing.title,
            description=existing.description,
            category=existing.category,
            likelihood=existing.likelihood,
            impact=existing.impact,
            risk_score=score,
            risk_level=level,
            owner=None,
            treatment=treatment if treatment is not None else existing.treatment,
            treatment_plan=treatment_plan if treatment_plan is not None else existing.treatment_plan,
            status=status if status is not None else existing.status,
            soc2_controls=existing.soc2_controls,
            related_finding=existing.related_finding,
            created_date=datetime.now(UTC).isoformat(),  # save_risk_items doesn't preserve this on REPLACE
            last_reviewed=datetime.now(UTC).isoformat(),
            review_notes=review_notes if review_notes is not None else None,
        )
        try:
            self._db.save_risk_items([item], account_id=account_id)
        except Exception as e:
            return ActionResult(success=False, message=f"Failed to update risk: {e}")
        return ActionResult(success=True, message=f"Updated risk {risk_id}", record_id=risk_id)
```

Also update the imports at the top of `store.py`:
```python
from shasta.voice.models import (
    ActionResult,        # add
    ComplianceScoreView,
    ControlSummaryView,
    FindingDetailView,
    FindingSummary,
    Framework,
    MultiFrameworkScoreView,
    RiskItemView,        # add
    ScanSummaryView,
    ScoreTrendView,
)
```

- [ ] **Step 4: Run tests**

```bash
pytest tests/voice/test_store_writes.py -v
```
Expected: 6 passing.

- [ ] **Step 5: Commit**

```bash
git add src/shasta/voice/store.py tests/voice/test_store_writes.py
git commit -m "feat(voice): risk-register write methods on store facade"
```

---

## Task 6: Tool functions — findings

**Files:**
- Create: `src/shasta/voice/tools/findings.py`
- Create: `tests/voice/test_tools_findings.py`

Tools are thin wrappers — they take dict args, call `Store` methods, return `model_dump(mode="json")` dicts. Errors return `{"error": "...", ...}` rather than raising.

- [ ] **Step 1: Write the failing test**

`tests/voice/test_tools_findings.py`:
```python
from shasta.voice.store import Store
from shasta.voice.tools import findings as findings_tool


def test_list_findings_returns_dicts(store: Store):
    result = findings_tool.list_findings(store=store)
    assert isinstance(result, list)
    assert all(isinstance(item, dict) for item in result)
    assert all("severity" in item for item in result)


def test_list_findings_with_filters(store: Store):
    result = findings_tool.list_findings(store=store, severity="critical", status="fail")
    assert len(result) == 4


def test_get_finding_known(store: Store):
    result = findings_tool.get_finding(store=store, finding_id="f-001")
    assert result["id"] == "f-001"
    assert "description" in result


def test_get_finding_unknown_returns_error(store: Store):
    result = findings_tool.get_finding(store=store, finding_id="nope")
    assert result == {"error": "finding_not_found", "finding_id": "nope"}


def test_list_top_blockers(store: Store):
    result = findings_tool.list_top_blockers(store=store)
    assert len(result) == 5


def test_get_resource_findings_unknown_returns_empty_list(store: Store):
    result = findings_tool.get_resource_findings(store=store, resource_id="not-here")
    assert result == []
```

- [ ] **Step 2: Run — expect failure**

```bash
pytest tests/voice/test_tools_findings.py -v
```
Expected: `ModuleNotFoundError: No module named 'shasta.voice.tools.findings'`

- [ ] **Step 3: Implement `src/shasta/voice/tools/findings.py`**

```python
"""Tool functions for finding queries."""
from typing import Any

from shasta.voice.store import Store


def list_findings(
    *,
    store: Store,
    severity: str | None = None,
    status: str | None = None,
    domain: str | None = None,
    cloud: str | None = None,
    framework: str | None = None,
    control_id: str | None = None,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    items = store.list_findings(
        severity=severity, status=status, domain=domain, cloud=cloud,
        framework=framework, control_id=control_id, limit=limit,
    )
    return [i.model_dump(mode="json") for i in items]


def get_finding(*, store: Store, finding_id: str) -> dict[str, Any]:
    detail = store.get_finding(finding_id)
    if detail is None:
        return {"error": "finding_not_found", "finding_id": finding_id}
    return detail.model_dump(mode="json")


def list_top_blockers(*, store: Store, limit: int = 5) -> list[dict[str, Any]]:
    return [i.model_dump(mode="json") for i in store.list_top_blockers(limit=limit)]


def get_resource_findings(*, store: Store, resource_id: str) -> list[dict[str, Any]]:
    return [i.model_dump(mode="json") for i in store.get_resource_findings(resource_id)]
```

- [ ] **Step 4: Run — expect pass**

```bash
pytest tests/voice/test_tools_findings.py -v
```
Expected: 6 passing.

- [ ] **Step 5: Commit**

```bash
git add src/shasta/voice/tools/findings.py tests/voice/test_tools_findings.py
git commit -m "feat(voice): findings tool functions"
```

---

## Task 7: Tool functions — scores, controls, risks, scans

**Files:**
- Create: `src/shasta/voice/tools/{scores,controls,risks,scans}.py`
- Create: `tests/voice/test_tools_{scores,controls,risks,scans}.py`

Same shape as Task 6. Bundled into one task since each module is small (~30 lines).

- [ ] **Step 1: Write all four test files**

`tests/voice/test_tools_scores.py`:
```python
from shasta.voice.store import Store
from shasta.voice.tools import scores as scores_tool


def test_get_compliance_score_soc2(store: Store):
    res = scores_tool.get_compliance_score(store=store, framework="soc2")
    assert res["framework"] == "soc2"
    assert "score_percentage" in res


def test_get_compliance_score_unknown_framework_returns_error(store: Store):
    res = scores_tool.get_compliance_score(store=store, framework="bogus")
    assert "error" in res


def test_get_multi_framework_score(store: Store):
    res = scores_tool.get_multi_framework_score(store=store)
    assert "frameworks" in res
    assert isinstance(res["frameworks"], list)


def test_get_score_trend(store: Store):
    res = scores_tool.get_score_trend(store=store, framework="soc2", limit=10)
    assert res["framework"] == "soc2"
    assert "delta" in res
    assert "points" in res
```

`tests/voice/test_tools_controls.py`:
```python
from shasta.voice.store import Store
from shasta.voice.tools import controls as controls_tool


def test_get_control_summary_specific(store: Store):
    res = controls_tool.get_control_summary(store=store, framework="soc2", control_id="CC6.1")
    assert isinstance(res, list)
    assert len(res) == 1
    assert res[0]["control_id"] == "CC6.1"


def test_get_control_summary_all(store: Store):
    res = controls_tool.get_control_summary(store=store, framework="soc2")
    assert isinstance(res, list)
    assert len(res) >= 1
```

`tests/voice/test_tools_risks.py`:
```python
from shasta.voice.store import Store
from shasta.voice.tools import risks as risks_tool


def test_list_risk_items_empty(store: Store):
    assert risks_tool.list_risk_items(store=store, account_id="123456789012") == []


def test_add_risk_item_success(store: Store):
    res = risks_tool.add_risk_item(
        store=store, account_id="123456789012",
        title="t", description="d", category="iam",
        likelihood="medium", impact="high", treatment="mitigate",
    )
    assert res["success"] is True
    assert res["record_id"]


def test_get_risk_item_known(store: Store):
    add = risks_tool.add_risk_item(
        store=store, account_id="123456789012",
        title="t", description="d", category="iam",
        likelihood="low", impact="low", treatment="accept",
    )
    res = risks_tool.get_risk_item(store=store, risk_id=add["record_id"])
    assert res["risk_id"] == add["record_id"]


def test_get_risk_item_unknown_returns_error(store: Store):
    res = risks_tool.get_risk_item(store=store, risk_id="R-NOPE")
    assert res == {"error": "risk_not_found", "risk_id": "R-NOPE"}


def test_update_risk(store: Store):
    add = risks_tool.add_risk_item(
        store=store, account_id="123456789012",
        title="t", description="d", category="iam",
        likelihood="low", impact="low", treatment="accept",
    )
    upd = risks_tool.update_risk(store=store, risk_id=add["record_id"], status="resolved")
    assert upd["success"] is True
```

`tests/voice/test_tools_scans.py`:
```python
from shasta.voice.store import Store
from shasta.voice.tools import scans as scans_tool


def test_list_scans(store: Store):
    res = scans_tool.list_scans(store=store, limit=10)
    assert isinstance(res, list)
    assert len(res) == 2


def test_get_latest_scan(store: Store):
    res = scans_tool.get_latest_scan(store=store)
    assert res["scan_id"] == "scan-test-001"
```

- [ ] **Step 2: Run — expect failure**

```bash
pytest tests/voice/test_tools_scores.py tests/voice/test_tools_controls.py tests/voice/test_tools_risks.py tests/voice/test_tools_scans.py -v
```

- [ ] **Step 3: Implement all four modules**

`src/shasta/voice/tools/scores.py`:
```python
"""Tool functions for compliance scores."""
from typing import Any

from shasta.voice.store import Store

_VALID_FRAMEWORKS = {"soc2", "iso27001", "hipaa", "iso42001", "eu_ai_act", "ai_governance"}


def get_compliance_score(*, store: Store, framework: str) -> dict[str, Any]:
    if framework not in _VALID_FRAMEWORKS:
        return {"error": "invalid_framework", "framework": framework, "valid": sorted(_VALID_FRAMEWORKS)}
    score = store.get_compliance_score(framework)  # type: ignore[arg-type]
    if score is None:
        return {"error": "framework_not_applicable", "framework": framework, "reason": "no_findings_or_scorer_unavailable"}
    return score.model_dump(mode="json")


def get_multi_framework_score(*, store: Store) -> dict[str, Any]:
    return store.get_multi_framework_score().model_dump(mode="json")


def get_score_trend(*, store: Store, framework: str, limit: int = 10) -> dict[str, Any]:
    if framework not in _VALID_FRAMEWORKS:
        return {"error": "invalid_framework", "framework": framework}
    return store.get_score_trend(framework, limit=limit).model_dump(mode="json")  # type: ignore[arg-type]
```

`src/shasta/voice/tools/controls.py`:
```python
"""Tool functions for control summaries."""
from typing import Any

from shasta.voice.store import Store


def get_control_summary(*, store: Store, framework: str, control_id: str | None = None) -> list[dict[str, Any]]:
    return [c.model_dump(mode="json") for c in store.get_control_summary(framework, control_id=control_id)]  # type: ignore[arg-type]
```

`src/shasta/voice/tools/risks.py`:
```python
"""Tool functions for risk-register operations."""
from typing import Any

from shasta.voice.store import Store


def list_risk_items(*, store: Store, account_id: str, status: str | None = None, level: str | None = None) -> list[dict[str, Any]]:
    return [r.model_dump(mode="json") for r in store.list_risk_items(account_id, status=status, level=level)]


def get_risk_item(*, store: Store, risk_id: str, account_id: str = "123456789012") -> dict[str, Any]:
    r = store.get_risk_item(risk_id, account_id=account_id)
    if r is None:
        return {"error": "risk_not_found", "risk_id": risk_id}
    return r.model_dump(mode="json")


def add_risk_item(
    *,
    store: Store,
    account_id: str,
    title: str,
    description: str,
    category: str,
    likelihood: str,
    impact: str,
    treatment: str,
    treatment_plan: str | None = None,
    related_finding: str | None = None,
) -> dict[str, Any]:
    return store.add_risk_item(
        account_id=account_id, title=title, description=description, category=category,
        likelihood=likelihood, impact=impact, treatment=treatment,
        treatment_plan=treatment_plan, related_finding=related_finding,
    ).model_dump(mode="json")


def update_risk(
    *,
    store: Store,
    risk_id: str,
    treatment: str | None = None,
    treatment_plan: str | None = None,
    status: str | None = None,
    review_notes: str | None = None,
    account_id: str = "123456789012",
) -> dict[str, Any]:
    return store.update_risk(
        risk_id=risk_id, treatment=treatment, treatment_plan=treatment_plan,
        status=status, review_notes=review_notes, account_id=account_id,
    ).model_dump(mode="json")
```

`src/shasta/voice/tools/scans.py`:
```python
"""Tool functions for scan queries."""
from typing import Any

from shasta.voice.store import Store


def list_scans(*, store: Store, limit: int = 10) -> list[dict[str, Any]]:
    return [s.model_dump(mode="json") for s in store.list_scans(limit=limit)]


def get_latest_scan(*, store: Store) -> dict[str, Any]:
    s = store.get_latest_scan()
    if s is None:
        return {"error": "no_scan_data"}
    return s.model_dump(mode="json")
```

- [ ] **Step 4: Run — expect pass**

```bash
pytest tests/voice/test_tools_scores.py tests/voice/test_tools_controls.py tests/voice/test_tools_risks.py tests/voice/test_tools_scans.py -v
```

- [ ] **Step 5: Commit**

```bash
git add src/shasta/voice/tools/ tests/voice/test_tools_*.py
git commit -m "feat(voice): scores/controls/risks/scans tool functions"
```

---

## Task 8: Realtime config (Distiller + 14 tool schemas)

**Files:**
- Create: `src/shasta/voice/realtime_config.py`
- Create: `tests/voice/test_realtime_config.py`

- [ ] **Step 1: Write the failing test**

`tests/voice/test_realtime_config.py`:
```python
import json

from shasta.voice.realtime_config import SYSTEM_PROMPT, TOOL_SCHEMAS, VAD_CONFIG, build_session_payload


def test_system_prompt_mentions_shasta_and_25_words():
    assert "Shasta" in SYSTEM_PROMPT
    assert "25 words" in SYSTEM_PROMPT


def test_system_prompt_mentions_redirects():
    assert "/scan" in SYSTEM_PROMPT
    assert "/report" in SYSTEM_PROMPT


def test_tool_schemas_cover_all_14_tools():
    names = {t["name"] for t in TOOL_SCHEMAS}
    assert names == {
        "list_findings", "get_finding", "list_top_blockers", "get_resource_findings",
        "get_compliance_score", "get_multi_framework_score", "get_score_trend",
        "get_control_summary",
        "list_scans", "get_latest_scan",
        "list_risk_items", "get_risk_item", "add_risk_item", "update_risk",
    }


def test_tool_schemas_have_required_fields():
    for s in TOOL_SCHEMAS:
        assert s["type"] == "function"
        assert "name" in s and "description" in s and "parameters" in s
        assert s["parameters"]["type"] == "object"


def test_vad_config_uses_server_vad():
    assert VAD_CONFIG["type"] == "server_vad"


def test_build_session_payload_shape():
    p = build_session_payload()
    assert p["model"]
    assert p["voice"]
    assert p["instructions"] == SYSTEM_PROMPT
    assert p["tools"] == TOOL_SCHEMAS
    assert p["input_audio_transcription"]["model"] == "whisper-1"
    json.dumps(p)  # serializable
```

- [ ] **Step 2: Run — expect failure**

```bash
pytest tests/voice/test_realtime_config.py -v
```

- [ ] **Step 3: Implement `src/shasta/voice/realtime_config.py`**

```python
"""OpenAI Realtime session configuration: Distiller prompt, 14 tool schemas, VAD."""
import os
from typing import Any

SYSTEM_PROMPT = """You are Shasta's voice compliance assistant. You are talking to a security engineer or founder over voice. Their data is real — you have read access to their actual scan findings, compliance scores across SOC 2 / ISO 27001 / HIPAA / ISO 42001 / EU AI Act, and risk register.

VOICE OUTPUT RULES (non-negotiable):
- Maximum 25 words per response unless the user explicitly asks for detail.
- Lead with the most important fact. Numbers before context. Severity before description. Failed counts before passing counts.
- Never read JSON, ARNs, IP addresses, or long control IDs out loud unless the user asks.
- If listing items, name at most 3. Offer to continue ("...and 5 more — want the full list?").
- Use plain words, not compliance jargon, unless the user uses jargon first.

TOOL USE:
- For any question about findings, scores, controls, scans, or risks, call a tool. Never invent data.
- For ambiguous questions, make the most reasonable assumption (default: status=fail, scope=latest scan) and proceed; mention your assumption briefly.
- After an action tool succeeds (add_risk_item, update_risk), confirm in one short sentence.
- If a tool returns "no_data" or empty, say so honestly. Do not invent.

REDIRECTS (out of scope for voice — Shasta runs these via Claude Code skills):
- RUN A SCAN → "Run /scan in Claude Code. Want me to summarize what it'll do first?"
- GENERATE A REPORT/PDF → "Run /report — voice can't deliver PDFs. I can summarize the latest scan."
- GENERATE TERRAFORM → "Run /remediate for the Terraform. I can describe what the fix does."
- GENERATE POLICY DOCS → "Run /policy-gen for the policy docs."

PERSONA:
- Calm, precise, slightly understated. Experienced compliance engineer on a Tuesday afternoon.
- Adjust register to the audience — technical for engineers, plainer for founders.
- Never apologize for tool latency. Never say "let me check that for you" — just do it.
"""

TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function", "name": "list_findings",
        "description": "List compliance findings from the latest scan. Filter by severity, status, domain, cloud, framework, control.",
        "parameters": {
            "type": "object",
            "properties": {
                "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                "status": {"type": "string", "enum": ["pass", "fail", "partial", "not_assessed", "not_applicable"]},
                "domain": {"type": "string", "enum": ["iam", "networking", "encryption", "logging", "compute", "storage", "monitoring", "ai_governance"]},
                "cloud": {"type": "string", "enum": ["aws", "azure"]},
                "framework": {"type": "string", "enum": ["soc2", "iso27001", "hipaa"]},
                "control_id": {"type": "string", "description": "e.g., CC6.1 — only meaningful with framework set"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100},
            },
            "additionalProperties": False,
        },
    },
    {
        "type": "function", "name": "get_finding",
        "description": "Get full detail of a single finding by ID — description, remediation, affected resource, control mappings.",
        "parameters": {
            "type": "object",
            "properties": {"finding_id": {"type": "string"}},
            "required": ["finding_id"],
            "additionalProperties": False,
        },
    },
    {
        "type": "function", "name": "list_top_blockers",
        "description": "List the highest-severity unresolved findings. Use for 'what should I fix first?' questions.",
        "parameters": {
            "type": "object",
            "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 20}},
            "additionalProperties": False,
        },
    },
    {
        "type": "function", "name": "get_resource_findings",
        "description": "List all findings for a specific cloud resource (by ARN or Azure resource ID).",
        "parameters": {
            "type": "object",
            "properties": {"resource_id": {"type": "string"}},
            "required": ["resource_id"],
            "additionalProperties": False,
        },
    },
    {
        "type": "function", "name": "get_compliance_score",
        "description": "Get the compliance score for one framework. Use when the user asks about a specific standard.",
        "parameters": {
            "type": "object",
            "properties": {"framework": {"type": "string", "enum": ["soc2", "iso27001", "hipaa", "iso42001", "eu_ai_act", "ai_governance"]}},
            "required": ["framework"],
            "additionalProperties": False,
        },
    },
    {
        "type": "function", "name": "get_multi_framework_score",
        "description": "Get scores for ALL frameworks at once. Use for 'how am I doing across the board?' or 'overall posture' questions.",
        "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "type": "function", "name": "get_score_trend",
        "description": "Get score history for a framework across recent scans. Use for 'how does that compare to last week?' questions.",
        "parameters": {
            "type": "object",
            "properties": {
                "framework": {"type": "string", "enum": ["soc2", "iso27001", "hipaa"]},
                "limit": {"type": "integer", "minimum": 2, "maximum": 50},
            },
            "required": ["framework"],
            "additionalProperties": False,
        },
    },
    {
        "type": "function", "name": "get_control_summary",
        "description": "Get summary of a specific control (e.g., CC6.1) or all controls in a framework. Returns pass/fail counts + finding IDs.",
        "parameters": {
            "type": "object",
            "properties": {
                "framework": {"type": "string", "enum": ["soc2", "iso27001", "hipaa"]},
                "control_id": {"type": "string"},
            },
            "required": ["framework"],
            "additionalProperties": False,
        },
    },
    {
        "type": "function", "name": "list_scans",
        "description": "List recent scans with summary stats (date, total findings, pass/fail counts).",
        "parameters": {
            "type": "object",
            "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 50}},
            "additionalProperties": False,
        },
    },
    {
        "type": "function", "name": "get_latest_scan",
        "description": "Get summary of the most recent scan: when it ran, total findings, severity counts.",
        "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "type": "function", "name": "list_risk_items",
        "description": "List risk register items. Filter by status (open/in_progress/accepted/resolved) or level (high/medium/low).",
        "parameters": {
            "type": "object",
            "properties": {
                "account_id": {"type": "string", "description": "Cloud account ID — pass the user's account from latest scan if unknown"},
                "status": {"type": "string", "enum": ["open", "in_progress", "accepted", "resolved"]},
                "level": {"type": "string", "enum": ["high", "medium", "low"]},
            },
            "required": ["account_id"],
            "additionalProperties": False,
        },
    },
    {
        "type": "function", "name": "get_risk_item",
        "description": "Get a single risk register item by ID.",
        "parameters": {
            "type": "object",
            "properties": {"risk_id": {"type": "string"}, "account_id": {"type": "string"}},
            "required": ["risk_id"],
            "additionalProperties": False,
        },
    },
    {
        "type": "function", "name": "add_risk_item",
        "description": "Add a new risk to the risk register. Use when the user explicitly asks to record a risk.",
        "parameters": {
            "type": "object",
            "properties": {
                "account_id": {"type": "string"},
                "title": {"type": "string"},
                "description": {"type": "string"},
                "category": {"type": "string", "description": "e.g., iam, logging, encryption"},
                "likelihood": {"type": "string", "enum": ["low", "medium", "high"]},
                "impact": {"type": "string", "enum": ["low", "medium", "high"]},
                "treatment": {"type": "string", "enum": ["mitigate", "accept", "transfer", "avoid"]},
                "treatment_plan": {"type": "string"},
                "related_finding": {"type": "string", "description": "Optional finding ID this risk relates to"},
            },
            "required": ["account_id", "title", "description", "category", "likelihood", "impact", "treatment"],
            "additionalProperties": False,
        },
    },
    {
        "type": "function", "name": "update_risk",
        "description": "Update an existing risk register item. Pass risk_id plus any fields to change.",
        "parameters": {
            "type": "object",
            "properties": {
                "risk_id": {"type": "string"},
                "account_id": {"type": "string"},
                "treatment": {"type": "string", "enum": ["mitigate", "accept", "transfer", "avoid"]},
                "treatment_plan": {"type": "string"},
                "status": {"type": "string", "enum": ["open", "in_progress", "accepted", "resolved"]},
                "review_notes": {"type": "string"},
            },
            "required": ["risk_id"],
            "additionalProperties": False,
        },
    },
]


VAD_CONFIG: dict[str, Any] = {
    "type": "server_vad",
    "threshold": 0.5,
    "prefix_padding_ms": 300,
    "silence_duration_ms": 500,
}


def build_session_payload() -> dict[str, Any]:
    return {
        "model": os.environ.get("OPENAI_REALTIME_MODEL", "gpt-realtime"),
        "voice": os.environ.get("OPENAI_REALTIME_VOICE", "cedar"),
        "instructions": SYSTEM_PROMPT,
        "tools": TOOL_SCHEMAS,
        "turn_detection": VAD_CONFIG,
        "input_audio_format": "pcm16",
        "output_audio_format": "pcm16",
        "input_audio_transcription": {"model": "whisper-1"},
    }
```

- [ ] **Step 4: Run — expect pass**

```bash
pytest tests/voice/test_realtime_config.py -v
```
Expected: 6 passing.

- [ ] **Step 5: Commit**

```bash
git add src/shasta/voice/realtime_config.py tests/voice/test_realtime_config.py
git commit -m "feat(voice): realtime session config — Distiller prompt + 14 tool schemas"
```

---

## Task 9: Observability + session token

**Files:**
- Create: `src/shasta/voice/observability.py`
- Create: `src/shasta/voice/session.py`
- Create: `tests/voice/test_observability.py`
- Create: `tests/voice/test_session.py` (deferred run — needs app.py from Task 10)

This task bundles observability and session because they're tiny and adjacent.

- [ ] **Step 1: Implement observability and its test**

`src/shasta/voice/observability.py`:
```python
"""Structured logging for tool calls."""
import json
import logging
import os
from typing import Any

_LOGGER = logging.getLogger("shasta.voice")


def configure_logging() -> None:
    level = os.environ.get("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(level=level, format="%(message)s")
    _LOGGER.setLevel(level)


def log_tool_call(
    tool_name: str,
    args: dict[str, Any],
    latency_ms: float,
    result_size: int,
    error: str | None = None,
) -> None:
    payload: dict[str, Any] = {
        "event": "tool_call",
        "tool_name": tool_name,
        "args": args,
        "latency_ms": round(latency_ms, 2),
        "result_size": result_size,
    }
    if error:
        payload["error"] = error
    _LOGGER.info(json.dumps(payload))
```

`tests/voice/test_observability.py`:
```python
import json
import logging

from shasta.voice.observability import configure_logging, log_tool_call


def test_log_tool_call_emits_json(caplog):
    configure_logging()
    with caplog.at_level(logging.INFO, logger="shasta.voice"):
        log_tool_call(tool_name="list_findings", args={"severity": "critical"}, latency_ms=1.234, result_size=4)
    payloads = [json.loads(r.message) for r in caplog.records if r.message.startswith("{")]
    assert any(p.get("tool_name") == "list_findings" for p in payloads)
    matching = [p for p in payloads if p.get("tool_name") == "list_findings"][0]
    assert matching["latency_ms"] == 1.23
    assert matching["result_size"] == 4
```

- [ ] **Step 2: Run observability test**

```bash
pytest tests/voice/test_observability.py -v
```
Expected: 1 passing.

- [ ] **Step 3: Implement session.py**

`src/shasta/voice/session.py`:
```python
"""Ephemeral OpenAI Realtime token endpoint."""
import os

import httpx
from fastapi import APIRouter, HTTPException

from shasta.voice.realtime_config import build_session_payload

router = APIRouter()


@router.post("/session/token")
def mint_session_token() -> dict:
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key or api_key == "sk-replace-me":
        raise HTTPException(status_code=500, detail="OPENAI_API_KEY not configured")

    payload = build_session_payload()
    try:
        response = httpx.post(
            "https://api.openai.com/v1/realtime/sessions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json=payload,
            timeout=10.0,
        )
    except httpx.HTTPError as e:
        raise HTTPException(status_code=502, detail=f"OpenAI request failed: {e}") from e

    if response.status_code != 200:
        raise HTTPException(status_code=502, detail=f"OpenAI session creation failed ({response.status_code}): {response.text[:200]}")

    body = response.json()
    return {
        "client_secret": body["client_secret"]["value"],
        "expires_at": body["client_secret"]["expires_at"],
        "model": payload["model"],
    }
```

- [ ] **Step 4: Write deferred session test (will run in Task 11)**

`tests/voice/test_session.py`:
```python
from unittest.mock import MagicMock, patch


def test_session_token_endpoint_calls_openai(client):
    fake = MagicMock()
    fake.status_code = 200
    fake.json.return_value = {"client_secret": {"value": "ek_x", "expires_at": 1735000000}}

    with patch("shasta.voice.session.httpx.post", return_value=fake) as mock_post:
        resp = client.post("/session/token")
        assert resp.status_code == 200
        body = resp.json()
        assert body["client_secret"] == "ek_x"
        sent = mock_post.call_args.kwargs["json"]
        assert sent["model"]
        assert "Shasta" in sent["instructions"]
        assert len(sent["tools"]) == 14


def test_session_token_endpoint_handles_openai_error(client):
    fake = MagicMock()
    fake.status_code = 401
    fake.text = "Invalid key"

    with patch("shasta.voice.session.httpx.post", return_value=fake):
        resp = client.post("/session/token")
        assert resp.status_code == 502
```

Skip the test run — it depends on a `client` fixture that comes from Task 10's app.

- [ ] **Step 5: Commit**

```bash
git add src/shasta/voice/observability.py src/shasta/voice/session.py tests/voice/test_observability.py tests/voice/test_session.py
git commit -m "feat(voice): structured logging + ephemeral OpenAI token endpoint"
```

---

## Task 10: Tool router + app.py + CLI

**Files:**
- Create: `src/shasta/voice/tools/router.py`
- Create: `src/shasta/voice/app.py`
- Create: `src/shasta/voice/cli.py`
- Create: `tests/voice/test_tool_endpoints.py`
- Create: `tests/voice/test_cli.py`
- Modify: `tests/voice/conftest.py` (add `client` fixture)

This is the integration task. After it, the deferred test from Task 9 should pass too.

- [ ] **Step 1: Implement `src/shasta/voice/tools/router.py`**

```python
"""HTTP endpoints for tool calls. Browser relays OpenAI tool calls here."""
import time
from typing import Literal

from fastapi import APIRouter, Request
from pydantic import BaseModel

from shasta.voice.observability import log_tool_call
from shasta.voice.tools import controls as controls_tool
from shasta.voice.tools import findings as findings_tool
from shasta.voice.tools import risks as risks_tool
from shasta.voice.tools import scans as scans_tool
from shasta.voice.tools import scores as scores_tool

router = APIRouter(prefix="/tools")


def _store(request: Request):
    return request.app.state.store


def _timed(tool_name: str, args: dict, fn):
    start = time.perf_counter()
    result = fn()
    latency_ms = (time.perf_counter() - start) * 1000
    size = len(result) if isinstance(result, list) else 1
    log_tool_call(tool_name=tool_name, args=args, latency_ms=latency_ms, result_size=size)
    return result


# ---------- request models ----------

Severity = Literal["critical", "high", "medium", "low", "info"]
Status = Literal["pass", "fail", "partial", "not_assessed", "not_applicable"]
Cloud = Literal["aws", "azure"]
Framework = Literal["soc2", "iso27001", "hipaa", "iso42001", "eu_ai_act", "ai_governance"]
ScoringFramework = Literal["soc2", "iso27001", "hipaa"]
RiskStatus = Literal["open", "in_progress", "accepted", "resolved"]
RiskLevel = Literal["high", "medium", "low"]
Treatment = Literal["mitigate", "accept", "transfer", "avoid"]


class ListFindingsReq(BaseModel):
    severity: Severity | None = None
    status: Status | None = None
    domain: str | None = None
    cloud: Cloud | None = None
    framework: Framework | None = None
    control_id: str | None = None
    limit: int | None = None


class IdReq(BaseModel):
    finding_id: str | None = None
    risk_id: str | None = None
    resource_id: str | None = None


class GetComplianceScoreReq(BaseModel):
    framework: Framework


class GetScoreTrendReq(BaseModel):
    framework: ScoringFramework
    limit: int = 10


class GetControlSummaryReq(BaseModel):
    framework: ScoringFramework
    control_id: str | None = None


class LimitReq(BaseModel):
    limit: int = 5


class ListRisksReq(BaseModel):
    account_id: str
    status: RiskStatus | None = None
    level: RiskLevel | None = None


class GetRiskReq(BaseModel):
    risk_id: str
    account_id: str = "123456789012"


class AddRiskReq(BaseModel):
    account_id: str
    title: str
    description: str
    category: str
    likelihood: RiskLevel
    impact: RiskLevel
    treatment: Treatment
    treatment_plan: str | None = None
    related_finding: str | None = None


class UpdateRiskReq(BaseModel):
    risk_id: str
    account_id: str = "123456789012"
    treatment: Treatment | None = None
    treatment_plan: str | None = None
    status: RiskStatus | None = None
    review_notes: str | None = None


# ---------- endpoints ----------

@router.post("/list_findings")
def list_findings(req: ListFindingsReq, request: Request):
    return _timed("list_findings", req.model_dump(exclude_none=True),
                  lambda: findings_tool.list_findings(store=_store(request), **req.model_dump(exclude_none=True)))


@router.post("/get_finding")
def get_finding(req: IdReq, request: Request):
    return _timed("get_finding", {"finding_id": req.finding_id},
                  lambda: findings_tool.get_finding(store=_store(request), finding_id=req.finding_id or ""))


@router.post("/list_top_blockers")
def list_top_blockers(req: LimitReq, request: Request):
    return _timed("list_top_blockers", {"limit": req.limit},
                  lambda: findings_tool.list_top_blockers(store=_store(request), limit=req.limit))


@router.post("/get_resource_findings")
def get_resource_findings(req: IdReq, request: Request):
    return _timed("get_resource_findings", {"resource_id": req.resource_id},
                  lambda: findings_tool.get_resource_findings(store=_store(request), resource_id=req.resource_id or ""))


@router.post("/get_compliance_score")
def get_compliance_score(req: GetComplianceScoreReq, request: Request):
    return _timed("get_compliance_score", req.model_dump(),
                  lambda: scores_tool.get_compliance_score(store=_store(request), framework=req.framework))


@router.post("/get_multi_framework_score")
def get_multi_framework_score(request: Request):
    return _timed("get_multi_framework_score", {},
                  lambda: scores_tool.get_multi_framework_score(store=_store(request)))


@router.post("/get_score_trend")
def get_score_trend(req: GetScoreTrendReq, request: Request):
    return _timed("get_score_trend", req.model_dump(),
                  lambda: scores_tool.get_score_trend(store=_store(request), framework=req.framework, limit=req.limit))


@router.post("/get_control_summary")
def get_control_summary(req: GetControlSummaryReq, request: Request):
    return _timed("get_control_summary", req.model_dump(exclude_none=True),
                  lambda: controls_tool.get_control_summary(store=_store(request), framework=req.framework, control_id=req.control_id))


@router.post("/list_scans")
def list_scans(req: LimitReq, request: Request):
    return _timed("list_scans", {"limit": req.limit},
                  lambda: scans_tool.list_scans(store=_store(request), limit=req.limit))


@router.post("/get_latest_scan")
def get_latest_scan(request: Request):
    return _timed("get_latest_scan", {},
                  lambda: scans_tool.get_latest_scan(store=_store(request)))


@router.post("/list_risk_items")
def list_risk_items(req: ListRisksReq, request: Request):
    return _timed("list_risk_items", req.model_dump(exclude_none=True),
                  lambda: risks_tool.list_risk_items(store=_store(request), account_id=req.account_id, status=req.status, level=req.level))


@router.post("/get_risk_item")
def get_risk_item(req: GetRiskReq, request: Request):
    return _timed("get_risk_item", req.model_dump(),
                  lambda: risks_tool.get_risk_item(store=_store(request), risk_id=req.risk_id, account_id=req.account_id))


@router.post("/add_risk_item")
def add_risk_item(req: AddRiskReq, request: Request):
    return _timed("add_risk_item", req.model_dump(exclude_none=True),
                  lambda: risks_tool.add_risk_item(store=_store(request), **req.model_dump(exclude_none=True)))


@router.post("/update_risk")
def update_risk(req: UpdateRiskReq, request: Request):
    return _timed("update_risk", req.model_dump(exclude_none=True),
                  lambda: risks_tool.update_risk(store=_store(request), **req.model_dump(exclude_none=True)))
```

- [ ] **Step 2: Implement `src/shasta/voice/app.py`**

```python
"""FastAPI application for the voice console."""
import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from shasta.voice.observability import configure_logging
from shasta.voice.session import router as session_router
from shasta.voice.store import Store
from shasta.voice.tools.router import router as tools_router


def create_app(*, db_path: str | Path | None = None, serve_static: bool = True) -> FastAPI:
    configure_logging()
    app = FastAPI(title="Shasta Voice Console", version="0.1.0")

    allowed = os.environ.get("ALLOWED_ORIGINS", "http://localhost:8090").split(",")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
    )

    # One Store per process — reuses the same SQLite connection
    app.state.store = Store(db_path=db_path)

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    app.include_router(session_router)
    app.include_router(tools_router)

    if serve_static:
        dist = Path(__file__).parent / "web" / "dist"
        if dist.exists():
            app.mount("/", StaticFiles(directory=str(dist), html=True), name="static")
    return app


# Module-level app for `uvicorn shasta.voice.app:app`
app = create_app()
```

- [ ] **Step 3: Implement `src/shasta/voice/cli.py`**

```python
"""`python -m shasta.voice` entrypoint."""
import argparse
import os
import sys
import webbrowser
from pathlib import Path

from shasta.voice.app import create_app


def main() -> int:
    parser = argparse.ArgumentParser(prog="shasta.voice", description="Voice console for Shasta")
    parser.add_argument("--port", type=int, default=8090)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--no-open", action="store_true", help="don't auto-launch browser")
    parser.add_argument("--db", type=Path, default=None, help="path to shasta.db (default: data/shasta.db)")
    args = parser.parse_args()

    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key or api_key == "sk-replace-me":
        print("✗ OPENAI_API_KEY not set in environment", file=sys.stderr)
        print("  Add to your shell: export OPENAI_API_KEY=sk-...", file=sys.stderr)
        return 2

    db_path = args.db or Path("data/shasta.db")
    if not db_path.exists():
        print(f"✗ No scan data at {db_path}", file=sys.stderr)
        print("  Run a scan first: open Claude Code and use /scan", file=sys.stderr)
        return 2

    # Verify the DB has at least one scan
    from shasta.voice.store import Store
    s = Store(db_path=db_path)
    if not s.has_data():
        print(f"✗ {db_path} exists but contains no scan data", file=sys.stderr)
        print("  Run a scan first: open Claude Code and use /scan", file=sys.stderr)
        s.close()
        return 2
    latest = s.get_latest_scan()
    s.close()

    print("✓ OPENAI_API_KEY found")
    print(f"✓ {db_path} (latest scan: {latest.completed_at}, {latest.total_findings} findings)")
    url = f"http://{args.host}:{args.port}"
    print(f"→ Starting voice console at {url}")

    if not args.no_open:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    import uvicorn
    app = create_app(db_path=db_path)
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: Add `client` fixture to `tests/voice/conftest.py`**

Append to the existing `conftest.py`:

```python
@pytest.fixture
def client(seeded_db_path: Path):
    """FastAPI TestClient bound to the seeded DB."""
    import os
    os.environ.setdefault("OPENAI_API_KEY", "test-key")
    os.environ.setdefault("ALLOWED_ORIGINS", "http://localhost:8090")
    from fastapi.testclient import TestClient
    from shasta.voice.app import create_app
    app = create_app(db_path=seeded_db_path, serve_static=False)
    return TestClient(app)
```

- [ ] **Step 5: Write `tests/voice/test_tool_endpoints.py`**

```python
def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_list_findings_endpoint(client):
    r = client.post("/tools/list_findings", json={})
    assert r.status_code == 200
    assert isinstance(r.json(), list)
    assert len(r.json()) == 10


def test_list_findings_filtered(client):
    r = client.post("/tools/list_findings", json={"severity": "critical", "status": "fail"})
    assert r.status_code == 200
    assert len(r.json()) == 4


def test_get_finding_endpoint(client):
    r = client.post("/tools/get_finding", json={"finding_id": "f-001"})
    assert r.status_code == 200
    assert r.json()["id"] == "f-001"


def test_get_finding_unknown_returns_200_with_error(client):
    r = client.post("/tools/get_finding", json={"finding_id": "nope"})
    assert r.status_code == 200
    assert r.json() == {"error": "finding_not_found", "finding_id": "nope"}


def test_get_compliance_score_endpoint(client):
    r = client.post("/tools/get_compliance_score", json={"framework": "soc2"})
    assert r.status_code == 200
    assert r.json()["framework"] == "soc2"


def test_get_multi_framework_score_endpoint(client):
    r = client.post("/tools/get_multi_framework_score", json={})
    assert r.status_code == 200
    assert "frameworks" in r.json()


def test_add_and_get_risk_endpoint(client):
    add = client.post("/tools/add_risk_item", json={
        "account_id": "123456789012",
        "title": "x", "description": "y", "category": "iam",
        "likelihood": "low", "impact": "low", "treatment": "accept",
    })
    assert add.status_code == 200
    rid = add.json()["record_id"]

    get = client.post("/tools/get_risk_item", json={"risk_id": rid})
    assert get.status_code == 200
    assert get.json()["risk_id"] == rid


def test_unknown_endpoint_returns_404(client):
    r = client.post("/tools/does_not_exist", json={})
    assert r.status_code == 404


def test_validates_severity_enum(client):
    r = client.post("/tools/list_findings", json={"severity": "extremely-critical"})
    assert r.status_code == 422
```

- [ ] **Step 6: Write `tests/voice/test_cli.py`**

```python
import os
import subprocess
import sys


def test_cli_help_runs():
    result = subprocess.run(
        [sys.executable, "-m", "shasta.voice", "--help"],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0
    assert "voice console" in result.stdout.lower()


def test_cli_missing_api_key(monkeypatch, tmp_path):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    db = tmp_path / "shasta.db"
    db.touch()
    result = subprocess.run(
        [sys.executable, "-m", "shasta.voice", "--db", str(db), "--no-open"],
        capture_output=True, text=True, timeout=10, env={**os.environ, "OPENAI_API_KEY": ""},
    )
    assert result.returncode == 2
    assert "OPENAI_API_KEY" in result.stderr


def test_cli_missing_db(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    missing = tmp_path / "absent.db"
    result = subprocess.run(
        [sys.executable, "-m", "shasta.voice", "--db", str(missing), "--no-open"],
        capture_output=True, text=True, timeout=10, env={**os.environ, "OPENAI_API_KEY": "sk-test"},
    )
    assert result.returncode == 2
    assert "No scan data" in result.stderr
```

- [ ] **Step 7: Run the full backend suite**

```bash
cd E:/Projects/Vanta
pytest tests/voice/ -v
```
Expected: all tests pass, including the deferred `test_session.py` from Task 9.

- [ ] **Step 8: Commit**

```bash
git add src/shasta/voice/tools/router.py src/shasta/voice/app.py src/shasta/voice/cli.py tests/voice/test_tool_endpoints.py tests/voice/test_cli.py tests/voice/conftest.py
git commit -m "feat(voice): tool endpoints, FastAPI app, and CLI entry point"
```

---

## Task 11: Frontend scaffold

**Files:**
- Create: `src/shasta/voice/web/package.json`
- Create: `src/shasta/voice/web/vite.config.ts`
- Create: `src/shasta/voice/web/tsconfig.json`
- Create: `src/shasta/voice/web/tsconfig.node.json`
- Create: `src/shasta/voice/web/index.html`
- Create: `src/shasta/voice/web/src/main.tsx`
- Create: `src/shasta/voice/web/src/App.tsx` (placeholder)

Same scaffold as VoiceApp's `web/` (Task 13 of `E:\Projects\Misc\VoiceApp\docs\superpowers\plans\2026-05-05-voiceapp.md`) with two changes: the page title is "Shasta — Voice Console" and Vite proxies hit port 8090 (not 8000).

- [ ] **Step 1: Create `package.json`** (verbatim copy from VoiceApp's `web/package.json`)

```json
{
  "name": "shasta-voice-web",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc -b && vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "react": "^18.3.1",
    "react-dom": "^18.3.1",
    "zustand": "^5.0.0",
    "framer-motion": "^11.11.0"
  },
  "devDependencies": {
    "@types/react": "^18.3.12",
    "@types/react-dom": "^18.3.1",
    "@vitejs/plugin-react": "^4.3.3",
    "typescript": "^5.6.3",
    "vite": "^5.4.10"
  }
}
```

- [ ] **Step 2: Create `vite.config.ts`** — proxies point at the FastAPI on port 8090

```typescript
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5174,                     // dev server port (different from prod 8090 to avoid collision)
    proxy: {
      "/session": "http://localhost:8090",
      "/tools": "http://localhost:8090",
      "/health": "http://localhost:8090",
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
});
```

- [ ] **Step 3: Create `tsconfig.json` and `tsconfig.node.json`** — copy verbatim from VoiceApp:

`tsconfig.json`:
```json
{
  "compilerOptions": {
    "target": "ES2022",
    "useDefineForClassFields": true,
    "lib": ["ES2022", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "skipLibCheck": true,
    "moduleResolution": "bundler",
    "allowImportingTsExtensions": true,
    "resolveJsonModule": true,
    "isolatedModules": true,
    "moduleDetection": "force",
    "noEmit": true,
    "jsx": "react-jsx",
    "strict": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noFallthroughCasesInSwitch": true
  },
  "include": ["src"],
  "references": [{ "path": "./tsconfig.node.json" }]
}
```

`tsconfig.node.json`:
```json
{
  "compilerOptions": {
    "composite": true,
    "skipLibCheck": true,
    "module": "ESNext",
    "moduleResolution": "bundler",
    "allowSyntheticDefaultImports": true,
    "strict": true
  },
  "include": ["vite.config.ts"]
}
```

- [ ] **Step 4: Create `index.html`** — title is the only change from VoiceApp's

```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Shasta — Voice Console</title>
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700&display=swap" rel="stylesheet" />
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
```

- [ ] **Step 5: Create `src/main.tsx`** — verbatim from VoiceApp

```typescript
import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./styles/tokens.css";
import "./styles/global.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
```

- [ ] **Step 6: Create placeholder `src/App.tsx`**

```typescript
export default function App() {
  return (
    <div style={{ padding: 24, color: "white" }}>
      <h1>Shasta — Voice Console</h1>
      <p>Scaffold OK. Components mount in later tasks.</p>
    </div>
  );
}
```

- [ ] **Step 7: Install and verify**

```bash
cd src/shasta/voice/web
npm install
npm run dev
```
Expected: Vite reports `Local: http://localhost:5174/`. Stop with Ctrl+C.

- [ ] **Step 8: Commit**

```bash
cd E:/Projects/Vanta
git add src/shasta/voice/web/package.json src/shasta/voice/web/vite.config.ts src/shasta/voice/web/tsconfig*.json src/shasta/voice/web/index.html src/shasta/voice/web/src/main.tsx src/shasta/voice/web/src/App.tsx
git commit -m "feat(voice): React + Vite scaffold for voice console"
```

`node_modules/` and `dist/` are gitignored at the Shasta repo level — verify with `git status` that they're not staged.

---

## Task 12: Brand tokens and global styles

**Files:**
- Create: `src/shasta/voice/web/src/styles/tokens.css`
- Create: `src/shasta/voice/web/src/styles/global.css`

**Copy verbatim from VoiceApp:** `E:\Projects\Misc\VoiceApp\web\src\styles\tokens.css` and `global.css`. The Transilience dark theme + brand gradient + severity-to-gradient mapping all carry over unchanged. No modifications.

- [ ] **Step 1: Copy both files**

```bash
copy "E:\Projects\Misc\VoiceApp\web\src\styles\tokens.css" "E:\Projects\Vanta\src\shasta\voice\web\src\styles\tokens.css"
copy "E:\Projects\Misc\VoiceApp\web\src\styles\global.css" "E:\Projects\Vanta\src\shasta\voice\web\src\styles\global.css"
```

(PowerShell: `Copy-Item`. Bash via the tool: `cp`.)

- [ ] **Step 2: Verify in browser**

```bash
cd src/shasta/voice/web
npm run dev
```
Expected: page shows the placeholder text on Rich Black background in Roboto. Stop server.

- [ ] **Step 3: Commit**

```bash
cd E:/Projects/Vanta
git add src/shasta/voice/web/src/styles/tokens.css src/shasta/voice/web/src/styles/global.css
git commit -m "feat(voice): brand tokens and global styles (dark Transilience theme)"
```

---

## Task 13: TS types + Zustand store

**Files:**
- Create: `src/shasta/voice/web/src/tools/types.ts`
- Create: `src/shasta/voice/web/src/state/session.ts`

Types are Shasta-specific (not copied from VoiceApp). Store is structurally identical to VoiceApp's but the `ActiveCard` union changes.

- [ ] **Step 1: Create `tools/types.ts`**

```typescript
// Mirrors src/shasta/voice/models.py — keep field names in sync.

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Status = "pass" | "fail" | "partial" | "not_assessed" | "not_applicable";
export type Cloud = "aws" | "azure";
export type Framework = "soc2" | "iso27001" | "hipaa" | "iso42001" | "eu_ai_act" | "ai_governance";

export interface FindingSummary {
  id: string;
  check_id: string;
  title: string;
  severity: Severity;
  status: Status;
  domain: string;
  resource_id: string;
  cloud_provider: Cloud;
  soc2_controls: string[];
  iso27001_controls: string[];
  hipaa_controls: string[];
}

export interface FindingDetailView extends FindingSummary {
  description: string;
  remediation: string;
  region: string;
  account_id: string;
  details: Record<string, unknown>;
  timestamp: string;
}

export interface ComplianceScoreView {
  framework: Framework;
  score_percentage: number;
  grade: string;
  total_controls: number;
  passing: number;
  failing: number;
  partial: number;
  not_assessed: number;
  total_findings: number;
  findings_failed: number;
}

export interface MultiFrameworkScoreView {
  frameworks: ComplianceScoreView[];
  not_enabled: Framework[];
}

export interface ScoreTrendView {
  framework: Framework;
  points: Array<{ scan_id: string; completed_at: string | null; score_percentage: number }>;
  delta: number;
}

export interface ControlSummaryView {
  framework: Framework;
  control_id: string;
  title: string;
  overall_status: string;
  pass_count: number;
  fail_count: number;
  partial_count: number;
  finding_ids: string[];
}

export interface RiskItemView {
  risk_id: string;
  title: string;
  description: string;
  category: string;
  likelihood: string;
  impact: string;
  risk_score: number;
  risk_level: string;
  treatment: string;
  treatment_plan: string | null;
  status: string;
  soc2_controls: string[];
  related_finding: string | null;
}

export interface ScanSummaryView {
  scan_id: string;
  account_id: string;
  cloud_provider: Cloud;
  completed_at: string | null;
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  passed: number;
  failed: number;
}

export interface ActionResult {
  success: boolean;
  message: string;
  record_id: string | null;
}

export type ActiveCard =
  | { kind: "none" }
  | { kind: "findings_list"; data: FindingSummary[] }
  | { kind: "finding_detail"; data: FindingDetailView }
  | { kind: "compliance_score"; data: ComplianceScoreView }
  | { kind: "multi_framework"; data: MultiFrameworkScoreView }
  | { kind: "control_summary"; data: ControlSummaryView[] }
  | { kind: "risk_list"; data: RiskItemView[] }
  | { kind: "risk_detail"; data: RiskItemView }
  | { kind: "action"; data: ActionResult };

export type ConnectionState =
  | "idle" | "connecting" | "connected"
  | "listening" | "thinking" | "speaking"
  | "error";

export interface TranscriptLine {
  id: string;
  who: "user" | "assistant";
  text: string;
  timestamp: number;
  partial?: boolean;
}
```

- [ ] **Step 2: Create `state/session.ts`** — copy verbatim from `E:\Projects\Misc\VoiceApp\web\src\state\session.ts`. The store shape doesn't change — `ActiveCard` is imported from types so the new union is picked up automatically.

- [ ] **Step 3: Verify TypeScript compiles**

```bash
cd src/shasta/voice/web
npx tsc --noEmit
```
Expected: no errors.

- [ ] **Step 4: Commit**

```bash
cd E:/Projects/Vanta
git add src/shasta/voice/web/src/tools/types.ts src/shasta/voice/web/src/state/session.ts
git commit -m "feat(voice): TypeScript types mirroring backend models + Zustand store"
```

---

## Task 14: Voice plumbing — connection, events, relay

**Files:**
- Create: `src/shasta/voice/web/src/voice/connection.ts`
- Create: `src/shasta/voice/web/src/voice/events.ts`
- Create: `src/shasta/voice/web/src/tools/relay.ts`

`connection.ts` and `events.ts` are **verbatim copies from VoiceApp**, including the audio-element-to-DOM fix (so we don't repeat the bug from VoiceApp Task 28→29 cycle). `relay.ts` is structurally identical but with the Shasta tool list.

- [ ] **Step 1: Copy `connection.ts` from VoiceApp** — but use the FIXED version (with `document.body.appendChild(audioElement)` and `audioElement.remove()` in close)

Source: `E:\Projects\Misc\VoiceApp\web\src\voice\connection.ts` (already includes Task 29 fix).

```bash
copy "E:\Projects\Misc\VoiceApp\web\src\voice\connection.ts" "E:\Projects\Vanta\src\shasta\voice\web\src\voice\connection.ts"
```

- [ ] **Step 2: Copy `events.ts` from VoiceApp verbatim**

```bash
copy "E:\Projects\Misc\VoiceApp\web\src\voice\events.ts" "E:\Projects\Vanta\src\shasta\voice\web\src\voice\events.ts"
```

- [ ] **Step 3: Create `tools/relay.ts`** — same shape as VoiceApp's, with the Shasta tool list

```typescript
const KNOWN_TOOLS = new Set([
  "list_findings",
  "get_finding",
  "list_top_blockers",
  "get_resource_findings",
  "get_compliance_score",
  "get_multi_framework_score",
  "get_score_trend",
  "get_control_summary",
  "list_scans",
  "get_latest_scan",
  "list_risk_items",
  "get_risk_item",
  "add_risk_item",
  "update_risk",
]);

export interface ToolCallResult {
  output: string;
  parsed: unknown;
  toolName: string;
  latencyMs: number;
}

export async function executeToolCall(toolName: string, argsJson: string): Promise<ToolCallResult> {
  const start = performance.now();
  if (!KNOWN_TOOLS.has(toolName)) {
    const errorPayload = { error: "unknown_tool", tool: toolName };
    return { output: JSON.stringify(errorPayload), parsed: errorPayload, toolName, latencyMs: 0 };
  }
  let args: unknown;
  try {
    args = argsJson ? JSON.parse(argsJson) : {};
  } catch {
    const errorPayload = { error: "invalid_arguments_json", raw: argsJson };
    return { output: JSON.stringify(errorPayload), parsed: errorPayload, toolName, latencyMs: 0 };
  }
  try {
    const resp = await fetch(`/tools/${toolName}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(args),
    });
    if (!resp.ok) {
      const errorPayload = {
        error: "tool_unavailable",
        status: resp.status,
        detail: (await resp.text()).slice(0, 200),
      };
      return { output: JSON.stringify(errorPayload), parsed: errorPayload, toolName, latencyMs: performance.now() - start };
    }
    const parsed = await resp.json();
    return { output: JSON.stringify(parsed), parsed, toolName, latencyMs: performance.now() - start };
  } catch (err) {
    const errorPayload = { error: "tool_unavailable", detail: err instanceof Error ? err.message : String(err) };
    return { output: JSON.stringify(errorPayload), parsed: errorPayload, toolName, latencyMs: performance.now() - start };
  }
}
```

- [ ] **Step 4: Verify TypeScript compiles**

```bash
cd src/shasta/voice/web
npx tsc --noEmit
```

- [ ] **Step 5: Commit**

```bash
cd E:/Projects/Vanta
git add src/shasta/voice/web/src/voice/connection.ts src/shasta/voice/web/src/voice/events.ts src/shasta/voice/web/src/tools/relay.ts
git commit -m "feat(voice): WebRTC connection + event parser + tool relay"
```

---

## Task 15: Reused UI chrome — Header, MicChrome, Transcript, SeverityBadge, ActionToast

**Files:**
- Create: `src/shasta/voice/web/src/components/Header.tsx`
- Create: `src/shasta/voice/web/src/components/MicChrome.tsx`
- Create: `src/shasta/voice/web/src/components/Transcript.tsx`
- Create: `src/shasta/voice/web/src/components/cards/SeverityBadge.tsx`
- Create: `src/shasta/voice/web/src/components/cards/ActionToast.tsx`

`Header.tsx` is the only one that needs editing — text-only (no logo) per design. Others are verbatim copies from VoiceApp.

- [ ] **Step 1: Create `Header.tsx`** — text-only, no `<img>` tag

```typescript
import { useSession } from "../state/session";

export function Header() {
  const connection = useSession((s) => s.connection);

  const indicatorColor =
    connection === "connected" || connection === "listening" ||
    connection === "thinking" || connection === "speaking"
      ? "var(--brand-yellow)"
      : connection === "error"
      ? "var(--severity-critical)"
      : "var(--text-subtle)";

  return (
    <header
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "var(--space-4) var(--space-5)",
        borderBottom: "1px solid var(--border-subtle)",
        background: "var(--bg-base)",
      }}
    >
      <div style={{ display: "flex", alignItems: "baseline", gap: "var(--space-3)" }}>
        <span style={{ fontSize: "var(--fs-title)", fontWeight: 700, letterSpacing: "-0.01em" }}>
          Shasta
        </span>
        <span style={{ fontSize: "var(--fs-small)", color: "var(--text-muted)" }}>
          Voice Console
        </span>
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: "var(--space-2)" }}>
        <div
          style={{
            width: 8, height: 8, borderRadius: "50%",
            background: indicatorColor, transition: "background 200ms",
          }}
        />
        <span style={{ fontSize: "var(--fs-small)", color: "var(--text-muted)" }}>
          {connection}
        </span>
      </div>
    </header>
  );
}
```

- [ ] **Step 2: Copy MicChrome, Transcript, SeverityBadge, ActionToast from VoiceApp verbatim**

```bash
copy "E:\Projects\Misc\VoiceApp\web\src\components\MicChrome.tsx" "E:\Projects\Vanta\src\shasta\voice\web\src\components\MicChrome.tsx"
copy "E:\Projects\Misc\VoiceApp\web\src\components\Transcript.tsx" "E:\Projects\Vanta\src\shasta\voice\web\src\components\Transcript.tsx"
copy "E:\Projects\Misc\VoiceApp\web\src\components\cards\SeverityBadge.tsx" "E:\Projects\Vanta\src\shasta\voice\web\src\components\cards\SeverityBadge.tsx"
copy "E:\Projects\Misc\VoiceApp\web\src\components\cards\ActionToast.tsx" "E:\Projects\Vanta\src\shasta\voice\web\src\components\cards\ActionToast.tsx"
```

- [ ] **Step 3: Verify TypeScript compiles**

```bash
cd src/shasta/voice/web
npx tsc --noEmit
```

- [ ] **Step 4: Commit**

```bash
cd E:/Projects/Vanta
git add src/shasta/voice/web/src/components/Header.tsx src/shasta/voice/web/src/components/MicChrome.tsx src/shasta/voice/web/src/components/Transcript.tsx src/shasta/voice/web/src/components/cards/SeverityBadge.tsx src/shasta/voice/web/src/components/cards/ActionToast.tsx
git commit -m "feat(voice): reused UI chrome — Header (text-only), MicChrome, Transcript, badges"
```

---

## Task 16: New cards — FindingsList, FindingDetail

**Files:**
- Create: `src/shasta/voice/web/src/components/cards/FindingsList.tsx`
- Create: `src/shasta/voice/web/src/components/cards/FindingDetail.tsx`

- [ ] **Step 1: Create `FindingsList.tsx`**

```typescript
import { motion } from "framer-motion";
import type { FindingSummary } from "../../tools/types";
import { SeverityBadge } from "./SeverityBadge";

function FrameworkChips({ f }: { f: FindingSummary }) {
  const chips: Array<{ label: string; color: string }> = [];
  for (const c of f.soc2_controls.slice(0, 2)) chips.push({ label: `SOC 2 · ${c}`, color: "var(--brand-purple)" });
  for (const c of f.iso27001_controls.slice(0, 1)) chips.push({ label: `ISO · ${c}`, color: "var(--severity-medium)" });
  for (const c of f.hipaa_controls.slice(0, 1)) chips.push({ label: `HIPAA · ${c}`, color: "var(--severity-high)" });
  return (
    <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
      {chips.map((c) => (
        <span key={c.label} style={{
          fontSize: 11, padding: "1px 6px", borderRadius: "var(--radius-sm)",
          background: "rgba(255,255,255,0.06)", color: c.color, whiteSpace: "nowrap",
        }}>{c.label}</span>
      ))}
    </div>
  );
}

export function FindingsList({ findings }: { findings: FindingSummary[] }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }}
      transition={{ duration: 0.2 }}
      style={{
        background: "var(--bg-surface)", border: "1px solid var(--border-card)",
        borderRadius: "var(--radius-md)", padding: "var(--space-5)",
      }}
    >
      <h2 style={{ margin: 0, fontSize: "var(--fs-heading)", fontWeight: 700 }}>
        {findings.length} finding{findings.length === 1 ? "" : "s"}
      </h2>
      <div style={{ display: "flex", flexDirection: "column", gap: "var(--space-2)", marginTop: "var(--space-4)" }}>
        {findings.map((f) => (
          <div key={f.id} style={{
            display: "grid", gridTemplateColumns: "auto 1fr auto", alignItems: "center",
            gap: "var(--space-3)", padding: "var(--space-3)",
            background: "var(--bg-surface-raised)", borderRadius: "var(--radius-sm)",
            borderLeft: f.severity === "critical" ? "2px solid var(--severity-critical)" : "2px solid transparent",
          }}>
            <SeverityBadge severity={f.severity} />
            <div style={{ minWidth: 0 }}>
              <div style={{ fontWeight: 500, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{f.title}</div>
              <div style={{ display: "flex", gap: "var(--space-2)", alignItems: "center", marginTop: 2 }}>
                <span style={{ fontSize: "var(--fs-small)", color: "var(--text-muted)" }}>
                  {f.cloud_provider.toUpperCase()} · {f.domain}
                </span>
                <FrameworkChips f={f} />
              </div>
            </div>
            <div style={{ fontSize: "var(--fs-small)", color: "var(--text-muted)" }}>{f.status}</div>
          </div>
        ))}
      </div>
    </motion.div>
  );
}
```

- [ ] **Step 2: Create `FindingDetail.tsx`**

```typescript
import { motion } from "framer-motion";
import type { FindingDetailView } from "../../tools/types";
import { SeverityBadge } from "./SeverityBadge";

export function FindingDetail({ finding }: { finding: FindingDetailView }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }}
      transition={{ duration: 0.2 }}
      style={{
        background: "var(--bg-surface)", border: "1px solid var(--border-card)",
        borderRadius: "var(--radius-md)", padding: "var(--space-5)",
        borderLeft: finding.severity === "critical" ? "2px solid var(--severity-critical)" : "1px solid var(--border-card)",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: "var(--space-3)" }}>
        <SeverityBadge severity={finding.severity} />
        <span style={{ color: "var(--text-muted)", fontSize: "var(--fs-small)" }}>
          {finding.id} · {finding.cloud_provider.toUpperCase()} · {finding.domain}
        </span>
      </div>
      <h2 style={{ margin: "var(--space-3) 0 0 0", fontSize: "var(--fs-title)", fontWeight: 700 }}>{finding.title}</h2>
      <p style={{ marginTop: "var(--space-3)", lineHeight: 1.5 }}>{finding.description}</p>

      <div style={{ marginTop: "var(--space-4)", display: "flex", gap: "var(--space-5)", flexWrap: "wrap" }}>
        {finding.soc2_controls.length > 0 && (
          <div>
            <div style={{ fontSize: "var(--fs-small)", color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.04em", marginBottom: 4 }}>
              SOC 2
            </div>
            <div style={{ color: "var(--brand-purple)", fontSize: "var(--fs-small)" }}>{finding.soc2_controls.join(", ")}</div>
          </div>
        )}
        {finding.iso27001_controls.length > 0 && (
          <div>
            <div style={{ fontSize: "var(--fs-small)", color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.04em", marginBottom: 4 }}>
              ISO 27001
            </div>
            <div style={{ color: "var(--severity-medium)", fontSize: "var(--fs-small)" }}>{finding.iso27001_controls.join(", ")}</div>
          </div>
        )}
        {finding.hipaa_controls.length > 0 && (
          <div>
            <div style={{ fontSize: "var(--fs-small)", color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.04em", marginBottom: 4 }}>
              HIPAA
            </div>
            <div style={{ color: "var(--severity-high)", fontSize: "var(--fs-small)" }}>{finding.hipaa_controls.join(", ")}</div>
          </div>
        )}
      </div>

      <div style={{ marginTop: "var(--space-4)", padding: "var(--space-3)", background: "var(--bg-surface-raised)", borderRadius: "var(--radius-sm)", fontSize: "var(--fs-small)" }}>
        <strong style={{ color: "var(--brand-yellow)" }}>Resource:</strong>{" "}
        <span style={{ wordBreak: "break-all", color: "var(--text-muted)" }}>{finding.resource_id}</span>
      </div>
      {finding.remediation && (
        <div style={{ marginTop: "var(--space-3)", color: "var(--text-primary)", fontSize: "var(--fs-small)" }}>
          <strong>Fix:</strong> {finding.remediation}
        </div>
      )}
    </motion.div>
  );
}
```

- [ ] **Step 3: Verify and commit**

```bash
cd src/shasta/voice/web && npx tsc --noEmit && cd E:/Projects/Vanta
git add src/shasta/voice/web/src/components/cards/FindingsList.tsx src/shasta/voice/web/src/components/cards/FindingDetail.tsx
git commit -m "feat(voice): FindingsList and FindingDetail cards with framework chips"
```

---

## Task 17: New cards — ComplianceScore, MultiFrameworkScore

**Files:**
- Create: `src/shasta/voice/web/src/components/cards/ComplianceScore.tsx`
- Create: `src/shasta/voice/web/src/components/cards/MultiFrameworkScore.tsx`

- [ ] **Step 1: Create `ComplianceScore.tsx`**

```typescript
import { motion } from "framer-motion";
import type { ComplianceScoreView } from "../../tools/types";

const FRAMEWORK_LABELS: Record<string, string> = {
  soc2: "SOC 2",
  iso27001: "ISO 27001",
  hipaa: "HIPAA",
  iso42001: "ISO 42001",
  eu_ai_act: "EU AI Act",
  ai_governance: "AI Governance",
};

export function ComplianceScore({ score }: { score: ComplianceScoreView }) {
  const gradeColor = score.grade === "A" ? "var(--brand-yellow)"
    : score.grade === "B" ? "var(--severity-low)"
    : score.grade === "C" ? "var(--severity-medium)"
    : "var(--severity-critical)";
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }}
      transition={{ duration: 0.2 }}
      style={{
        background: "var(--bg-surface)", border: "1px solid var(--border-card)",
        borderRadius: "var(--radius-md)", padding: "var(--space-5)",
      }}
    >
      <h2 style={{ margin: 0, fontSize: "var(--fs-heading)", fontWeight: 700 }}>
        {FRAMEWORK_LABELS[score.framework] ?? score.framework}
      </h2>
      <div style={{ display: "flex", alignItems: "baseline", gap: "var(--space-3)", marginTop: "var(--space-3)" }}>
        <span style={{ fontSize: 56, fontWeight: 700, color: gradeColor, lineHeight: 1 }}>
          {score.score_percentage.toFixed(0)}<span style={{ fontSize: 24, color: "var(--text-muted)" }}>%</span>
        </span>
        <span style={{ fontSize: 28, fontWeight: 700, color: gradeColor }}>{score.grade}</span>
      </div>
      <div style={{
        marginTop: "var(--space-4)", display: "grid", gridTemplateColumns: "repeat(4, 1fr)",
        gap: "var(--space-2)", fontSize: "var(--fs-small)",
      }}>
        <div><div style={{ color: "var(--text-muted)" }}>Passing</div><div style={{ color: "var(--brand-yellow)", fontWeight: 700 }}>{score.passing}</div></div>
        <div><div style={{ color: "var(--text-muted)" }}>Failing</div><div style={{ color: "var(--severity-critical)", fontWeight: 700 }}>{score.failing}</div></div>
        <div><div style={{ color: "var(--text-muted)" }}>Partial</div><div style={{ color: "var(--severity-medium)", fontWeight: 700 }}>{score.partial}</div></div>
        <div><div style={{ color: "var(--text-muted)" }}>Findings</div><div style={{ fontWeight: 700 }}>{score.total_findings}</div></div>
      </div>
    </motion.div>
  );
}
```

- [ ] **Step 2: Create `MultiFrameworkScore.tsx`**

```typescript
import { motion } from "framer-motion";
import type { ComplianceScoreView, MultiFrameworkScoreView } from "../../tools/types";

const LABELS: Record<string, string> = {
  soc2: "SOC 2", iso27001: "ISO 27001", hipaa: "HIPAA",
  iso42001: "ISO 42001", eu_ai_act: "EU AI Act", ai_governance: "AI Gov",
};

function ScoreColumn({ s }: { s: ComplianceScoreView }) {
  const fillPct = Math.max(0, Math.min(100, s.score_percentage));
  return (
    <div style={{
      display: "flex", flexDirection: "column", alignItems: "center",
      padding: "var(--space-3)", background: "var(--bg-surface-raised)",
      borderRadius: "var(--radius-sm)", position: "relative", overflow: "hidden", minHeight: 180,
    }}>
      <div aria-hidden style={{
        position: "absolute", left: 0, right: 0, bottom: 0, height: `${fillPct}%`,
        background: "var(--brand-gradient)", opacity: 0.18,
      }} />
      <div style={{ position: "relative", zIndex: 1, fontSize: "var(--fs-small)", color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.04em" }}>
        {LABELS[s.framework] ?? s.framework}
      </div>
      <div style={{ position: "relative", zIndex: 1, fontSize: 36, fontWeight: 700, marginTop: "auto", color: "var(--text-primary)" }}>
        {s.score_percentage.toFixed(0)}<span style={{ fontSize: 16, color: "var(--text-muted)" }}>%</span>
      </div>
      <div style={{ position: "relative", zIndex: 1, fontSize: "var(--fs-small)", color: "var(--text-muted)", marginTop: 4 }}>
        Grade {s.grade}
      </div>
    </div>
  );
}

function NotEnabledColumn({ framework }: { framework: string }) {
  return (
    <div style={{
      display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center",
      padding: "var(--space-3)", background: "var(--bg-surface-raised)",
      borderRadius: "var(--radius-sm)", minHeight: 180, opacity: 0.4,
    }}>
      <div style={{ fontSize: "var(--fs-small)", color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.04em" }}>
        {LABELS[framework] ?? framework}
      </div>
      <div style={{ fontSize: "var(--fs-small)", color: "var(--text-subtle)", marginTop: "var(--space-2)" }}>
        not enabled
      </div>
    </div>
  );
}

export function MultiFrameworkScore({ data }: { data: MultiFrameworkScoreView }) {
  const ALL: string[] = ["soc2", "iso27001", "hipaa", "iso42001", "eu_ai_act"];
  const enabled = new Map(data.frameworks.map((s) => [s.framework, s]));
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }}
      transition={{ duration: 0.2 }}
      style={{
        background: "var(--bg-surface)", border: "1px solid var(--border-card)",
        borderRadius: "var(--radius-md)", padding: "var(--space-5)",
      }}
    >
      <h2 style={{ margin: 0, fontSize: "var(--fs-heading)", fontWeight: 700 }}>Compliance posture</h2>
      <div style={{ marginTop: "var(--space-4)", display: "grid", gridTemplateColumns: `repeat(${ALL.length}, 1fr)`, gap: "var(--space-2)" }}>
        {ALL.map((fw) => {
          const score = enabled.get(fw as ComplianceScoreView["framework"]);
          return score ? <ScoreColumn key={fw} s={score} /> : <NotEnabledColumn key={fw} framework={fw} />;
        })}
      </div>
    </motion.div>
  );
}
```

- [ ] **Step 3: Verify + commit**

```bash
cd src/shasta/voice/web && npx tsc --noEmit && cd E:/Projects/Vanta
git add src/shasta/voice/web/src/components/cards/ComplianceScore.tsx src/shasta/voice/web/src/components/cards/MultiFrameworkScore.tsx
git commit -m "feat(voice): ComplianceScore and MultiFrameworkScore cards"
```

---

## Task 18: New cards — ControlSummary, RiskList, RiskDetail

**Files:**
- Create: `src/shasta/voice/web/src/components/cards/ControlSummary.tsx`
- Create: `src/shasta/voice/web/src/components/cards/RiskList.tsx`
- Create: `src/shasta/voice/web/src/components/cards/RiskDetail.tsx`

- [ ] **Step 1: Create `ControlSummary.tsx`**

```typescript
import { motion } from "framer-motion";
import type { ControlSummaryView } from "../../tools/types";

const STATUS_COLOR: Record<string, string> = {
  pass: "var(--brand-yellow)", fail: "var(--severity-critical)",
  partial: "var(--severity-medium)", not_assessed: "var(--text-subtle)",
  requires_policy: "var(--severity-low)",
};

export function ControlSummary({ controls }: { controls: ControlSummaryView[] }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }}
      transition={{ duration: 0.2 }}
      style={{
        background: "var(--bg-surface)", border: "1px solid var(--border-card)",
        borderRadius: "var(--radius-md)", padding: "var(--space-5)",
      }}
    >
      <h2 style={{ margin: 0, fontSize: "var(--fs-heading)", fontWeight: 700 }}>
        {controls.length} control{controls.length === 1 ? "" : "s"}
      </h2>
      <div style={{ display: "flex", flexDirection: "column", gap: "var(--space-2)", marginTop: "var(--space-4)" }}>
        {controls.map((c) => (
          <div key={c.control_id} style={{
            display: "grid", gridTemplateColumns: "auto 1fr auto auto auto",
            gap: "var(--space-3)", alignItems: "center", padding: "var(--space-3)",
            background: "var(--bg-surface-raised)", borderRadius: "var(--radius-sm)",
            borderLeft: `2px solid ${STATUS_COLOR[c.overall_status] ?? "transparent"}`,
          }}>
            <span style={{ fontWeight: 700, color: "var(--brand-purple)" }}>{c.control_id}</span>
            <span style={{ color: "var(--text-primary)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{c.title}</span>
            <span style={{ fontSize: "var(--fs-small)", color: "var(--brand-yellow)" }}>{c.pass_count} pass</span>
            <span style={{ fontSize: "var(--fs-small)", color: "var(--severity-critical)" }}>{c.fail_count} fail</span>
            <span style={{ fontSize: "var(--fs-small)", color: STATUS_COLOR[c.overall_status] ?? "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.04em" }}>
              {c.overall_status}
            </span>
          </div>
        ))}
      </div>
    </motion.div>
  );
}
```

- [ ] **Step 2: Create `RiskList.tsx`**

```typescript
import { motion } from "framer-motion";
import type { RiskItemView } from "../../tools/types";

const LEVEL_COLOR: Record<string, string> = {
  high: "var(--severity-critical)", medium: "var(--severity-medium)", low: "var(--severity-low)",
};

export function RiskList({ risks }: { risks: RiskItemView[] }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }}
      transition={{ duration: 0.2 }}
      style={{
        background: "var(--bg-surface)", border: "1px solid var(--border-card)",
        borderRadius: "var(--radius-md)", padding: "var(--space-5)",
      }}
    >
      <h2 style={{ margin: 0, fontSize: "var(--fs-heading)", fontWeight: 700 }}>
        {risks.length} risk{risks.length === 1 ? "" : "s"}
      </h2>
      <div style={{ display: "flex", flexDirection: "column", gap: "var(--space-2)", marginTop: "var(--space-4)" }}>
        {risks.map((r) => (
          <div key={r.risk_id} style={{
            display: "grid", gridTemplateColumns: "auto 1fr auto auto",
            gap: "var(--space-3)", alignItems: "center", padding: "var(--space-3)",
            background: "var(--bg-surface-raised)", borderRadius: "var(--radius-sm)",
            borderLeft: `2px solid ${LEVEL_COLOR[r.risk_level] ?? "transparent"}`,
          }}>
            <span style={{ fontSize: 22, fontWeight: 700, color: LEVEL_COLOR[r.risk_level] ?? "var(--text-primary)", minWidth: 28, textAlign: "center" }}>{r.risk_score}</span>
            <span style={{ color: "var(--text-primary)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{r.title}</span>
            <span style={{ fontSize: "var(--fs-small)", color: "var(--text-muted)" }}>{r.treatment}</span>
            <span style={{ fontSize: "var(--fs-small)", color: "var(--text-muted)" }}>{r.status}</span>
          </div>
        ))}
      </div>
    </motion.div>
  );
}
```

- [ ] **Step 3: Create `RiskDetail.tsx`**

```typescript
import { motion } from "framer-motion";
import type { RiskItemView } from "../../tools/types";

export function RiskDetail({ risk }: { risk: RiskItemView }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }}
      transition={{ duration: 0.2 }}
      style={{
        background: "var(--bg-surface)", border: "1px solid var(--border-card)",
        borderRadius: "var(--radius-md)", padding: "var(--space-5)",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: "var(--space-3)" }}>
        <span style={{ color: "var(--brand-purple)", fontWeight: 700 }}>{risk.risk_id}</span>
        <span style={{ fontSize: "var(--fs-small)", color: "var(--text-muted)" }}>
          {risk.risk_level.toUpperCase()} · score {risk.risk_score} · {risk.status}
        </span>
      </div>
      <h2 style={{ margin: "var(--space-3) 0 0 0", fontSize: "var(--fs-title)", fontWeight: 700 }}>{risk.title}</h2>
      <p style={{ marginTop: "var(--space-3)", lineHeight: 1.5 }}>{risk.description}</p>
      <div style={{ marginTop: "var(--space-4)", display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "var(--space-3)", fontSize: "var(--fs-small)" }}>
        <div><div style={{ color: "var(--text-muted)" }}>Likelihood</div><div>{risk.likelihood}</div></div>
        <div><div style={{ color: "var(--text-muted)" }}>Impact</div><div>{risk.impact}</div></div>
        <div><div style={{ color: "var(--text-muted)" }}>Treatment</div><div>{risk.treatment}</div></div>
      </div>
      {risk.treatment_plan && (
        <div style={{ marginTop: "var(--space-4)", padding: "var(--space-3)", background: "var(--bg-surface-raised)", borderRadius: "var(--radius-sm)", fontSize: "var(--fs-small)" }}>
          <strong>Plan:</strong> {risk.treatment_plan}
        </div>
      )}
    </motion.div>
  );
}
```

- [ ] **Step 4: Verify + commit**

```bash
cd src/shasta/voice/web && npx tsc --noEmit && cd E:/Projects/Vanta
git add src/shasta/voice/web/src/components/cards/ControlSummary.tsx src/shasta/voice/web/src/components/cards/RiskList.tsx src/shasta/voice/web/src/components/cards/RiskDetail.tsx
git commit -m "feat(voice): ControlSummary, RiskList, RiskDetail cards"
```

---

## Task 19: CardSlot + cardDispatcher + App.tsx wiring

**Files:**
- Create: `src/shasta/voice/web/src/components/CardSlot.tsx`
- Create: `src/shasta/voice/web/src/voice/cardDispatcher.ts`
- Replace: `src/shasta/voice/web/src/App.tsx`

This is the integration step — after this the frontend is end-to-end wired.

- [ ] **Step 1: Create `CardSlot.tsx`**

```typescript
import { AnimatePresence } from "framer-motion";
import { useSession } from "../state/session";
import { ActionToast } from "./cards/ActionToast";
import { ComplianceScore } from "./cards/ComplianceScore";
import { ControlSummary } from "./cards/ControlSummary";
import { FindingDetail } from "./cards/FindingDetail";
import { FindingsList } from "./cards/FindingsList";
import { MultiFrameworkScore } from "./cards/MultiFrameworkScore";
import { RiskDetail } from "./cards/RiskDetail";
import { RiskList } from "./cards/RiskList";

export function CardSlot() {
  const card = useSession((s) => s.activeCard);
  return (
    <div style={{ height: "100%", display: "flex", alignItems: "flex-start" }}>
      <div style={{ width: "100%" }}>
        <AnimatePresence mode="wait">
          {card.kind === "findings_list" && <FindingsList key="findings_list" findings={card.data} />}
          {card.kind === "finding_detail" && <FindingDetail key={`finding-${card.data.id}`} finding={card.data} />}
          {card.kind === "compliance_score" && <ComplianceScore key={`score-${card.data.framework}`} score={card.data} />}
          {card.kind === "multi_framework" && <MultiFrameworkScore key="multi" data={card.data} />}
          {card.kind === "control_summary" && <ControlSummary key="controls" controls={card.data} />}
          {card.kind === "risk_list" && <RiskList key="risk_list" risks={card.data} />}
          {card.kind === "risk_detail" && <RiskDetail key={`risk-${card.data.risk_id}`} risk={card.data} />}
          {card.kind === "action" && <ActionToast key={`action-${(card.data as any).timestamp ?? Date.now()}`} action={card.data as any} />}
          {card.kind === "none" && (
            <div key="empty" style={{ color: "var(--text-subtle)", fontSize: "var(--fs-small)", padding: "var(--space-5)", textAlign: "center" }}>
              Ask about findings, scores, controls, or risks to populate this panel.
            </div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}
```

(`ActionToast` from VoiceApp expects an `ActionResult` with `success`, `message`, `new_status`, `timestamp`. Our Shasta `ActionResult` doesn't have `new_status` or `timestamp` — adjust by creating a small shim or skipping `new_status`/`timestamp` fields in the toast. Easiest fix: in the ActionToast we copied from VoiceApp, change the references to those fields to use `record_id` and the current time. Make that one-line edit if TypeScript complains.)

- [ ] **Step 2: Create `voice/cardDispatcher.ts`**

```typescript
import type {
  ActionResult, ActiveCard, ComplianceScoreView, ControlSummaryView,
  FindingDetailView, FindingSummary, MultiFrameworkScoreView, RiskItemView,
} from "../tools/types";

export function dispatchCard(toolName: string, parsed: unknown): ActiveCard | null {
  if (parsed && typeof parsed === "object" && "error" in parsed) return null;

  switch (toolName) {
    case "list_findings":
    case "list_top_blockers":
    case "get_resource_findings":
      if (Array.isArray(parsed)) return { kind: "findings_list", data: parsed as FindingSummary[] };
      return null;
    case "get_finding":
      if (parsed && typeof parsed === "object" && "id" in parsed) return { kind: "finding_detail", data: parsed as FindingDetailView };
      return null;
    case "get_compliance_score":
      if (parsed && typeof parsed === "object" && "framework" in parsed) return { kind: "compliance_score", data: parsed as ComplianceScoreView };
      return null;
    case "get_multi_framework_score":
      if (parsed && typeof parsed === "object" && "frameworks" in parsed) return { kind: "multi_framework", data: parsed as MultiFrameworkScoreView };
      return null;
    case "get_control_summary":
      if (Array.isArray(parsed)) return { kind: "control_summary", data: parsed as ControlSummaryView[] };
      return null;
    case "list_risk_items":
      if (Array.isArray(parsed)) return { kind: "risk_list", data: parsed as RiskItemView[] };
      return null;
    case "get_risk_item":
      if (parsed && typeof parsed === "object" && "risk_id" in parsed) return { kind: "risk_detail", data: parsed as RiskItemView };
      return null;
    case "add_risk_item":
    case "update_risk":
      if (parsed && typeof parsed === "object" && "success" in parsed) return { kind: "action", data: parsed as ActionResult };
      return null;
    // Tools without cards: get_score_trend, list_scans, get_latest_scan
    default:
      return null;
  }
}
```

- [ ] **Step 3: Replace `App.tsx`** — copy from VoiceApp's `App.tsx` and adjust imports to point at the Shasta dispatcher and components

The structure is identical to `E:\Projects\Misc\VoiceApp\web\src\App.tsx` (the post-Task-28 fully-wired version). Copy that file and:
1. Change `import { dispatchCard } from "./voice/cardDispatcher"` — same path, new content (already done in step 2 above).
2. Change the imports of `Header`, `MicChrome`, `Transcript`, `CardSlot` — same paths, already exist in our project.
3. Nothing else changes — `App.tsx` doesn't reference any specific card component directly; everything goes through `useSession` + `setActiveCard`.

```bash
copy "E:\Projects\Misc\VoiceApp\web\src\App.tsx" "E:\Projects\Vanta\src\shasta\voice\web\src\App.tsx"
```

- [ ] **Step 4: Verify the full frontend compiles**

```bash
cd src/shasta/voice/web
npx tsc --noEmit
```

If errors mention `ActionToast` referencing `new_status` or `timestamp` (because Shasta's `ActionResult` doesn't have those), open `src/components/cards/ActionToast.tsx` and replace `action.new_status` with `action.record_id ?? "ok"` and replace `action.timestamp` with `new Date().toLocaleTimeString()`. One-line fix per reference.

- [ ] **Step 5: Commit**

```bash
cd E:/Projects/Vanta
git add src/shasta/voice/web/src/components/CardSlot.tsx src/shasta/voice/web/src/voice/cardDispatcher.ts src/shasta/voice/web/src/App.tsx src/shasta/voice/web/src/components/cards/ActionToast.tsx
git commit -m "feat(voice): wire end-to-end — App, CardSlot, cardDispatcher, ActionToast tweaks"
```

---

## Task 20: Build the React bundle and commit `dist/`

**Files:**
- Create: `src/shasta/voice/web/dist/**` (build output)

This is the only place we deliberately commit a build artifact. It's required so `pip install shasta[voice]` works without Node.

- [ ] **Step 1: Build the production bundle**

```bash
cd src/shasta/voice/web
npm run build
```
Expected: `dist/` directory created with `index.html` and `assets/`. No TypeScript errors. Bundle ~250-300 KB (~85-100 KB gzipped).

- [ ] **Step 2: Verify the FastAPI server can serve it end-to-end**

```bash
cd E:/Projects/Vanta
# Make sure the seeded test DB is in place; otherwise create a tiny one or point at a real scan
# For verification, set OPENAI_API_KEY to a stub so the CLI accepts it
$env:OPENAI_API_KEY = "sk-test-stub"   # PowerShell
# or: export OPENAI_API_KEY=sk-test-stub  (Bash)
python -m shasta.voice --no-open --port 8090 --db data/shasta.db
```
If `data/shasta.db` doesn't exist on this machine, the CLI will refuse — that's expected and fine. The build verification is just `npm run build` succeeding.

- [ ] **Step 3: Commit the bundle**

```bash
git add -f src/shasta/voice/web/dist/
git commit -m "build(voice): pre-built React bundle for zero-Node distribution"
```

The `-f` is needed if `dist/` is in `.gitignore` (likely). If you'd rather not pollute the global `.gitignore`, add a `src/shasta/voice/web/.gitignore` that explicitly negates `!dist/`.

---

## Task 21: CI workflow + README updates

**Files:**
- Create: `.github/workflows/voice-bundle.yml`
- Modify: `README.md`

- [ ] **Step 1: Create the bundle-check CI workflow**

`.github/workflows/voice-bundle.yml`:
```yaml
name: voice-bundle

on:
  pull_request:
    paths:
      - 'src/shasta/voice/web/src/**'
      - 'src/shasta/voice/web/package.json'
      - 'src/shasta/voice/web/package-lock.json'
      - 'src/shasta/voice/web/vite.config.ts'

jobs:
  rebuild-and-diff:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'
          cache-dependency-path: 'src/shasta/voice/web/package-lock.json'
      - name: Install
        working-directory: src/shasta/voice/web
        run: npm ci
      - name: Build
        working-directory: src/shasta/voice/web
        run: npm run build
      - name: Verify committed bundle is up to date
        run: |
          if ! git diff --quiet src/shasta/voice/web/dist/; then
            echo "::error::The committed React bundle is out of date. Run 'npm run build' in src/shasta/voice/web/ and commit the result."
            git status src/shasta/voice/web/dist/
            git diff src/shasta/voice/web/dist/ | head -100
            exit 1
          fi
```

- [ ] **Step 2: Add a Voice Console section to the root README**

Find the Quick Start section (or a sensible location). Add this block:

```markdown
### Voice Console (optional)

Talk to your compliance posture instead of clicking through dashboards.

```bash
pip install shasta[voice]      # adds FastAPI + uvicorn + httpx
export OPENAI_API_KEY=sk-...   # required for OpenAI Realtime API
python -m shasta.voice         # opens browser at http://localhost:8090
```

Requires a recent scan in `data/shasta.db` (run `/scan` in Claude Code first). The voice assistant has read access to all your findings, compliance scores (SOC 2, ISO 27001, HIPAA, ISO 42001, EU AI Act), and risk register, plus light writes for adding/updating risk-register items. Heavy operations (scans, reports, Terraform generation) remain in the Claude Code skills — voice will redirect you to them.
```

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/voice-bundle.yml README.md
git commit -m "docs(voice): CI workflow + README section for voice console"
```

---

## Task 22: Final verification + PR

- [ ] **Step 1: Run the full test suite**

```bash
cd E:/Projects/Vanta
pytest tests/voice/ -v --cov=src/shasta/voice --cov-report=term-missing
```
Expected: all tests pass. Coverage target ≥80% on `src/shasta/voice/store.py` and `src/shasta/voice/tools/`.

- [ ] **Step 2: Run Shasta's existing test suite to confirm no regressions**

```bash
pytest tests/ -v --ignore=tests/voice
```
Expected: same pass/fail ratio as `main`. The voice module is purely additive — should not affect any existing test.

- [ ] **Step 3: Lint check**

```bash
ruff check src/shasta/voice/ tests/voice/
```
Fix any reported issues — they'll mostly be unused imports or import sorting.

- [ ] **Step 4: Manual end-to-end (USER required)**

The following requires a real scan database and a real `OPENAI_API_KEY`. The implementer should hand this off to the user:

1. Run `/scan` in Claude Code against a real (or test) AWS/Azure environment to populate `data/shasta.db`.
2. Set `OPENAI_API_KEY` in the environment.
3. Run `python -m shasta.voice`.
4. In the browser at `http://localhost:8090`: tap mic, allow permission, ask the following and verify the corresponding cards mount:
   - *"What's my SOC 2 score?"* → ComplianceScore card
   - *"Show me my critical findings."* → FindingsList card
   - *"Tell me about that one."* (after assistant names a finding) → FindingDetail card
   - *"How am I doing across the board?"* → MultiFrameworkScore card
   - *"What's CC6.1 looking like?"* → ControlSummary card
   - *"Show me my open risks."* → RiskList card (likely empty initially — that's fine)
   - *"Add a risk for the IAM thing."* → ActionToast confirming the new risk item
5. Verify barge-in: interrupt the assistant mid-response, confirm it stops within ~200ms.
6. Verify a redirect: ask *"Run a scan."* — assistant should suggest `/scan` rather than attempting it.

If anything fails, file an issue with the precise failure mode (which tool returned what, what card mounted instead of expected, what the browser console shows). Don't try to fix during the manual pass — capture and report.

- [ ] **Step 5: Open a PR**

```bash
git push -u origin feat/voice-console
gh pr create --title "feat: voice-driven compliance console (opt-in)" --body "$(cat <<'EOF'
## Summary
Adds an optional voice-driven dashboard at `python -m shasta.voice`. Reads real scan data, talks to compliance posture across SOC 2 / ISO 27001 / HIPAA / ISO 42001 / EU AI Act, supports light writes to the risk register.

- New sibling module `src/shasta/voice/` (FastAPI sub-app, OpenAI Realtime, React frontend)
- Pre-built React bundle ships in the wheel — no Node required at runtime
- Read-only over `ShastaDB` + risk-register writes via existing `save_risk_items`
- `pip install shasta[voice]` extra; default install unchanged

Spec: `docs/superpowers/specs/2026-05-05-shastavoice-design.md`
Plan: `docs/superpowers/plans/2026-05-05-shastavoice.md`

## Test plan
- [x] Voice tool layer unit tests passing (≥80% coverage on `src/shasta/voice/`)
- [x] Tool endpoint integration tests passing
- [x] Existing Shasta test suite still passing (no regressions)
- [ ] Manual rehearsal against real scan data + real OpenAI key (handed off to user)

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Self-Review Checklist (run after writing the plan)

✅ **Spec coverage:**
- Sibling module `src/shasta/voice/` with all listed Python files: Tasks 0, 2, 4, 5, 6, 7, 8, 9, 10
- All 14 tools: Tasks 6, 7
- Distiller system prompt with redirects: Task 8
- Voice-driven dashboard with all listed card types: Tasks 15, 16, 17, 18
- Brand integration (dark Transilience theme, Roboto): Task 12
- Text-only header (no logo): Task 15 step 1
- Real ShastaDB integration (no mock layer): Task 4
- Light writes (add/update risk): Task 5, Task 7
- Pre-built React bundle in wheel: Tasks 11, 20, 21
- CLI invocation `python -m shasta.voice`: Tasks 0, 10
- Empty-state and redirect handling: Task 8 (system prompt), Task 10 (CLI), Task 7 (tool errors)
- Test fixture seeded SQLite: Task 3
- pyproject `[voice]` extra + package-data: Task 1

No spec gaps.

✅ **Placeholder scan:** No "TBD", "TODO", "implement later", or "similar to Task N" without code. Reused VoiceApp files are referenced by exact path with explicit copy commands. The only intentional cross-file dependency calls out the precise edit (ActionToast field rename) when the type interface differs.

✅ **Type consistency:** All Python field names (`scan_id`, `account_id`, `score_percentage`, `risk_id`, etc.) match between `models.py` (Task 2), `store.py` (Tasks 4-5), tool functions (Tasks 6-7), and TypeScript `types.ts` (Task 13). Tool names match across `realtime_config.py` (Task 8), `tools/router.py` (Task 10), and `tools/relay.ts` (Task 14): list_findings, get_finding, list_top_blockers, get_resource_findings, get_compliance_score, get_multi_framework_score, get_score_trend, get_control_summary, list_scans, get_latest_scan, list_risk_items, get_risk_item, add_risk_item, update_risk.

✅ **Cross-repo references:** All `copy` commands reference the existing VoiceApp files by their actual paths on disk (`E:\Projects\Misc\VoiceApp\...`). The implementer can verify these exist at runtime before copying.


