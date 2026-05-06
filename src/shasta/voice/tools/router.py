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
