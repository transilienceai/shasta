"""Dashboard route handlers."""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse

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
from shasta.evidence.models import ScanSummary


def _enrich_all_frameworks(findings):
    """Ensure all framework mappings are populated on the findings list."""
    enrich_findings_with_controls(findings)
    enrich_findings_with_iso27001(findings)
    enrich_findings_with_hipaa(findings)
    return findings


router = APIRouter()


def _get_db() -> ShastaDB:
    db = ShastaDB()
    db.initialize()
    return db


def _templates():
    from shasta.dashboard.app import templates

    return templates


# ---------------------------------------------------------------------------
# GET / — Dashboard home
# ---------------------------------------------------------------------------
@router.get("/", response_class=HTMLResponse)
async def home(request: Request):
    db = _get_db()
    scan = db.get_latest_scan()

    if not scan:
        return _templates().TemplateResponse(
            "home.html",
            {"request": request, "scan": None, "no_data": True},
        )

    _enrich_all_frameworks(scan.findings)
    soc2_score = calculate_score(scan.findings)
    iso_score = calculate_iso27001_score(scan.findings)
    hipaa_score = calculate_hipaa_score(scan.findings)
    history = db.get_scan_history(limit=10)
    risks = db.get_risk_items(scan.account_id)

    # Whitney AI governance score (only if AI findings exist)
    whitney_score = None
    ai_findings = [f for f in scan.findings if f.domain.value == "ai_governance"]
    if ai_findings:
        try:
            from shasta.compliance.ai.scorer import calculate_ai_governance_score

            whitney_score = calculate_ai_governance_score(ai_findings)
        except ImportError:
            pass

    # Severity counts from summary
    summary = scan.summary or ScanSummary.from_findings(scan.findings)

    # Top 5 critical/high findings
    top_findings = [
        f
        for f in scan.findings
        if f.severity.value in ("critical", "high") and f.status.value == "fail"
    ][:5]

    # Parse history for trend data
    trend_data = _parse_history_scores(history)

    db.close()
    return _templates().TemplateResponse(
        "home.html",
        {
            "request": request,
            "scan": scan,
            "no_data": False,
            "soc2_score": soc2_score,
            "iso_score": iso_score,
            "hipaa_score": hipaa_score,
            "whitney_score": whitney_score,
            "summary": summary,
            "top_findings": top_findings,
            "trend_data": json.dumps(trend_data),
            "risk_count": len(risks),
        },
    )


# ---------------------------------------------------------------------------
# GET /findings — Filterable finding list
# ---------------------------------------------------------------------------
@router.get("/findings", response_class=HTMLResponse)
async def findings(
    request: Request,
    cloud: str | None = Query(None),
    domain: str | None = Query(None),
    severity: str | None = Query(None),
    status: str | None = Query(None),
):
    db = _get_db()
    scan = db.get_latest_scan()
    db.close()

    if not scan:
        return _templates().TemplateResponse(
            "findings.html",
            {"request": request, "findings": [], "total": 0, "filters": {}, "no_data": True},
        )

    filtered = scan.findings
    if cloud:
        filtered = [f for f in filtered if f.cloud_provider.value == cloud]
    if domain:
        filtered = [f for f in filtered if f.domain.value == domain]
    if severity:
        filtered = [f for f in filtered if f.severity.value == severity]
    if status:
        filtered = [f for f in filtered if f.status.value == status]

    filters = {
        "cloud": cloud or "",
        "domain": domain or "",
        "severity": severity or "",
        "status": status or "",
    }

    # If HTMX request, return just the table partial
    if request.headers.get("HX-Request"):
        return _templates().TemplateResponse(
            "partials/findings_table.html",
            {
                "request": request,
                "findings": filtered,
                "total": len(scan.findings),
                "shown": len(filtered),
            },
        )

    return _templates().TemplateResponse(
        "findings.html",
        {
            "request": request,
            "findings": filtered,
            "total": len(scan.findings),
            "shown": len(filtered),
            "filters": filters,
            "no_data": False,
        },
    )


# ---------------------------------------------------------------------------
# GET /findings/{finding_id} — Finding detail
# ---------------------------------------------------------------------------
@router.get("/findings/{finding_id}", response_class=HTMLResponse)
async def finding_detail(request: Request, finding_id: str):
    db = _get_db()
    scan = db.get_latest_scan()
    db.close()

    finding = None
    if scan:
        _enrich_all_frameworks(scan.findings)
        for f in scan.findings:
            if f.id == finding_id:
                finding = f
                break

    if not finding:
        return HTMLResponse("<h1>Finding not found</h1>", status_code=404)

    # Get mapped controls
    soc2_controls = finding.soc2_controls
    cis_gcp_controls = finding.cis_gcp_controls
    iso_controls = finding.details.get("iso27001_controls", [])
    hipaa_controls = finding.details.get("hipaa_controls", [])

    return _templates().TemplateResponse(
        "finding_detail.html",
        {
            "request": request,
            "finding": finding,
            "soc2_controls": soc2_controls,
            "cis_gcp_controls": cis_gcp_controls,
            "iso_controls": iso_controls,
            "hipaa_controls": hipaa_controls,
            "details_json": json.dumps(finding.details, indent=2, default=str),
        },
    )


# ---------------------------------------------------------------------------
# GET /controls — Control status grid
# ---------------------------------------------------------------------------
@router.get("/controls", response_class=HTMLResponse)
async def controls(request: Request, framework: str = Query("soc2")):
    db = _get_db()
    scan = db.get_latest_scan()
    db.close()

    if not scan:
        return _templates().TemplateResponse(
            "controls.html",
            {"request": request, "controls": {}, "framework": framework, "no_data": True},
        )

    _enrich_all_frameworks(scan.findings)
    if framework == "iso27001":
        ctrl_summary = get_iso27001_control_summary(scan.findings)
    elif framework == "hipaa":
        ctrl_summary = get_hipaa_control_summary(scan.findings)
    else:
        ctrl_summary = get_control_summary(scan.findings)

    return _templates().TemplateResponse(
        "controls.html",
        {
            "request": request,
            "controls": ctrl_summary,
            "framework": framework,
            "no_data": False,
        },
    )


# ---------------------------------------------------------------------------
# GET /scans — Scan history
# ---------------------------------------------------------------------------
@router.get("/scans", response_class=HTMLResponse)
async def scans(request: Request):
    db = _get_db()
    history = db.get_scan_history(limit=20)
    db.close()

    # Parse summary JSON for each scan
    parsed = []
    for scan_row in history:
        entry: dict[str, Any] = dict(scan_row)
        if entry.get("summary"):
            try:
                raw = entry["summary"]
                s = json.loads(raw) if isinstance(raw, str) else raw
                entry["parsed_summary"] = s
            except (json.JSONDecodeError, TypeError):
                entry["parsed_summary"] = {}
        else:
            entry["parsed_summary"] = {}
        parsed.append(entry)

    return _templates().TemplateResponse(
        "scans.html",
        {"request": request, "scans": parsed},
    )


# ---------------------------------------------------------------------------
# GET /risks — Risk register
# ---------------------------------------------------------------------------
@router.get("/risks", response_class=HTMLResponse)
async def risks(request: Request):
    db = _get_db()
    scan = db.get_latest_scan()
    risk_items: list[dict] = []
    if scan:
        risk_items = db.get_risk_items(scan.account_id)
    db.close()

    return _templates().TemplateResponse(
        "risks.html",
        {"request": request, "risks": risk_items},
    )


# ---------------------------------------------------------------------------
# GET /api/summary — JSON API for Chart.js
# ---------------------------------------------------------------------------
@router.get("/api/summary")
async def api_summary():
    db = _get_db()
    scan = db.get_latest_scan()

    if not scan:
        return JSONResponse({"error": "No scan data available"}, status_code=404)

    soc2_score = calculate_score(scan.findings)
    iso_score = calculate_iso27001_score(scan.findings)
    hipaa_score = calculate_hipaa_score(scan.findings)
    summary = scan.summary or ScanSummary.from_findings(scan.findings)
    history = db.get_scan_history(limit=10)
    trend = _parse_history_scores(history)
    db.close()

    return JSONResponse(
        {
            "soc2": {
                "score": soc2_score.score_percentage,
                "grade": soc2_score.grade,
                "passing": soc2_score.passing,
                "failing": soc2_score.failing,
                "partial": soc2_score.partial,
            },
            "iso27001": {
                "score": iso_score.score_percentage,
                "grade": iso_score.grade,
                "passing": iso_score.passing,
                "failing": iso_score.failing,
                "partial": iso_score.partial,
            },
            "hipaa": {
                "score": hipaa_score.score_percentage,
                "grade": hipaa_score.grade,
                "passing": hipaa_score.passing,
                "failing": hipaa_score.failing,
                "partial": hipaa_score.partial,
            },
            "severity": {
                "critical": summary.critical_count,
                "high": summary.high_count,
                "medium": summary.medium_count,
                "low": summary.low_count,
                "info": summary.info_count,
            },
            "trend": trend,
        }
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _parse_history_scores(history: list[dict]) -> dict:
    """Extract score trend data from scan history."""
    dates = []
    soc2_scores = []
    iso_scores = []

    for scan_row in reversed(history):
        date_str = scan_row.get("started_at", "")
        if isinstance(date_str, str) and len(date_str) >= 10:
            dates.append(date_str[:10])
        else:
            dates.append(str(date_str))

        # Re-calculate scores from findings if we have them, otherwise estimate from summary
        summary_raw = scan_row.get("summary")
        if summary_raw:
            try:
                s = json.loads(summary_raw) if isinstance(summary_raw, str) else summary_raw
                total = s.get("total_findings", 0)
                passed = s.get("passed", 0)
                if total > 0:
                    pct = round((passed / total) * 100, 1)
                else:
                    pct = 0.0
                soc2_scores.append(pct)
                iso_scores.append(pct)
            except (json.JSONDecodeError, TypeError):
                soc2_scores.append(0)
                iso_scores.append(0)
        else:
            soc2_scores.append(0)
            iso_scores.append(0)

    return {
        "dates": dates,
        "soc2": soc2_scores,
        "iso27001": iso_scores,
    }
