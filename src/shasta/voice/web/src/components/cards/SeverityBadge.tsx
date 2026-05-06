import type { Severity } from "../../tools/types";

const COLORS: Record<Severity, { fg: string; bg: string }> = {
  critical: { fg: "var(--severity-critical)", bg: "var(--severity-critical-bg)" },
  high: { fg: "var(--severity-high)", bg: "var(--severity-high-bg)" },
  medium: { fg: "var(--severity-medium)", bg: "var(--severity-medium-bg)" },
  low: { fg: "var(--severity-low)", bg: "var(--severity-low-bg)" },
  info: { fg: "var(--text-muted)", bg: "rgba(255,255,255,0.08)" },
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  const { fg, bg } = COLORS[severity];
  return (
    <span
      style={{
        display: "inline-block",
        padding: "2px 8px",
        background: bg,
        color: fg,
        borderRadius: "var(--radius-sm)",
        fontSize: "var(--fs-small)",
        fontWeight: 700,
        textTransform: "uppercase",
        letterSpacing: "0.04em",
      }}
    >
      {severity}
    </span>
  );
}
