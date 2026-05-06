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
