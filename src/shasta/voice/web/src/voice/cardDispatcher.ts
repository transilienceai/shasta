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
