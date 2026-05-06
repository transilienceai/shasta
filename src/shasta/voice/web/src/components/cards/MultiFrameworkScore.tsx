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
