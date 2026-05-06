import { motion } from "framer-motion";
import type { FindingDetailView } from "../../tools/types";
import { SeverityBadge } from "./SeverityBadge";

export function FindingDetail({ finding }: { finding: FindingDetailView }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }}
      transition={{ duration: 0.2 }}
      style={{
        background: "var(--bg-surface)", border: "1px solid var(--border-card)",
        borderRadius: "var(--radius-md)", padding: "var(--space-5)",
        borderLeft: finding.severity === "critical" ? "2px solid var(--severity-critical)" : "1px solid var(--border-card)",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: "var(--space-3)" }}>
        <SeverityBadge severity={finding.severity} />
        <span style={{ color: "var(--text-muted)", fontSize: "var(--fs-small)" }}>
          {finding.id} · {finding.cloud_provider.toUpperCase()} · {finding.domain}
        </span>
      </div>
      <h2 style={{ margin: "var(--space-3) 0 0 0", fontSize: "var(--fs-title)", fontWeight: 700 }}>{finding.title}</h2>
      <p style={{ marginTop: "var(--space-3)", lineHeight: 1.5 }}>{finding.description}</p>

      <div style={{ marginTop: "var(--space-4)", display: "flex", gap: "var(--space-5)", flexWrap: "wrap" }}>
        {finding.soc2_controls.length > 0 && (
          <div>
            <div style={{ fontSize: "var(--fs-small)", color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.04em", marginBottom: 4 }}>
              SOC 2
            </div>
            <div style={{ color: "var(--brand-purple)", fontSize: "var(--fs-small)" }}>{finding.soc2_controls.join(", ")}</div>
          </div>
        )}
        {finding.iso27001_controls.length > 0 && (
          <div>
            <div style={{ fontSize: "var(--fs-small)", color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.04em", marginBottom: 4 }}>
              ISO 27001
            </div>
            <div style={{ color: "var(--severity-medium)", fontSize: "var(--fs-small)" }}>{finding.iso27001_controls.join(", ")}</div>
          </div>
        )}
        {finding.hipaa_controls.length > 0 && (
          <div>
            <div style={{ fontSize: "var(--fs-small)", color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.04em", marginBottom: 4 }}>
              HIPAA
            </div>
            <div style={{ color: "var(--severity-high)", fontSize: "var(--fs-small)" }}>{finding.hipaa_controls.join(", ")}</div>
          </div>
        )}
      </div>

      <div style={{ marginTop: "var(--space-4)", padding: "var(--space-3)", background: "var(--bg-surface-raised)", borderRadius: "var(--radius-sm)", fontSize: "var(--fs-small)" }}>
        <strong style={{ color: "var(--brand-yellow)" }}>Resource:</strong>{" "}
        <span style={{ wordBreak: "break-all", color: "var(--text-muted)" }}>{finding.resource_id}</span>
      </div>
      {finding.remediation && (
        <div style={{ marginTop: "var(--space-3)", color: "var(--text-primary)", fontSize: "var(--fs-small)" }}>
          <strong>Fix:</strong> {finding.remediation}
        </div>
      )}
    </motion.div>
  );
}
