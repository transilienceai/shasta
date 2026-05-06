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
