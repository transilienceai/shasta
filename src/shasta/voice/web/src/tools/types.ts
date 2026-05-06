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
