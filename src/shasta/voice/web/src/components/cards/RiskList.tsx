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
