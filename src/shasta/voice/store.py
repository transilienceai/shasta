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
    ActionResult,
    ComplianceScoreView,
    ControlSummaryView,
    FindingDetailView,
    FindingSummary,
    Framework,
    MultiFrameworkScoreView,
    RiskItemView,
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
