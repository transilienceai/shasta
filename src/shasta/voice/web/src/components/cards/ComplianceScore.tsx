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
