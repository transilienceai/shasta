import { motion } from "framer-motion";
import type { FindingSummary } from "../../tools/types";
import { SeverityBadge } from "./SeverityBadge";

function FrameworkChips({ f }: { f: FindingSummary }) {
  const chips: Array<{ label: string; color: string }> = [];
  for (const c of f.soc2_controls.slice(0, 2)) chips.push({ label: `SOC 2 · ${c}`, color: "var(--brand-purple)" });
  for (const c of f.iso27001_controls.slice(0, 1)) chips.push({ label: `ISO · ${c}`, color: "var(--severity-medium)" });
  for (const c of f.hipaa_controls.slice(0, 1)) chips.push({ label: `HIPAA · ${c}`, color: "var(--severity-high)" });
  return (
    <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
      {chips.map((c) => (
        <span key={c.label} style={{
          fontSize: 11, padding: "1px 6px", borderRadius: "var(--radius-sm)",
          background: "rgba(255,255,255,0.06)", color: c.color, whiteSpace: "nowrap",
        }}>{c.label}</span>
      ))}
    </div>
  );
}

export function FindingsList({ findings }: { findings: FindingSummary[] }) {
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
        {findings.length} finding{findings.length === 1 ? "" : "s"}
      </h2>
      <div style={{ display: "flex", flexDirection: "column", gap: "var(--space-2)", marginTop: "var(--space-4)" }}>
        {findings.map((f) => (
          <div key={f.id} style={{
            display: "grid", gridTemplateColumns: "auto 1fr auto", alignItems: "center",
            gap: "var(--space-3)", padding: "var(--space-3)",
            background: "var(--bg-surface-raised)", borderRadius: "var(--radius-sm)",
            borderLeft: f.severity === "critical" ? "2px solid var(--severity-critical)" : "2px solid transparent",
          }}>
            <SeverityBadge severity={f.severity} />
            <div style={{ minWidth: 0 }}>
              <div style={{ fontWeight: 500, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{f.title}</div>
              <div style={{ display: "flex", gap: "var(--space-2)", alignItems: "center", marginTop: 2 }}>
                <span style={{ fontSize: "var(--fs-small)", color: "var(--text-muted)" }}>
                  {f.cloud_provider.toUpperCase()} · {f.domain}
                </span>
                <FrameworkChips f={f} />
              </div>
            </div>
            <div style={{ fontSize: "var(--fs-small)", color: "var(--text-muted)" }}>{f.status}</div>
          </div>
        ))}
      </div>
    </motion.div>
  );
}
