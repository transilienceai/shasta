import { useSession } from "../state/session";

export function Header() {
  const connection = useSession((s) => s.connection);

  const indicatorColor =
    connection === "connected" || connection === "listening" ||
    connection === "thinking" || connection === "speaking"
      ? "var(--brand-yellow)"
      : connection === "error"
      ? "var(--severity-critical)"
      : "var(--text-subtle)";

  return (
    <header
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "var(--space-4) var(--space-5)",
        borderBottom: "1px solid var(--border-subtle)",
        background: "var(--bg-base)",
      }}
    >
      <div style={{ display: "flex", alignItems: "baseline", gap: "var(--space-3)" }}>
        <span style={{ fontSize: "var(--fs-title)", fontWeight: 700, letterSpacing: "-0.01em" }}>
          Shasta
        </span>
        <span style={{ fontSize: "var(--fs-small)", color: "var(--text-muted)" }}>
          Voice Console
        </span>
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: "var(--space-2)" }}>
        <div
          style={{
            width: 8, height: 8, borderRadius: "50%",
            background: indicatorColor, transition: "background 200ms",
          }}
        />
        <span style={{ fontSize: "var(--fs-small)", color: "var(--text-muted)" }}>
          {connection}
        </span>
      </div>
    </header>
  );
}
