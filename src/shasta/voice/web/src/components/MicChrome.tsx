import { useSession } from "../state/session";

interface MicChromeProps {
  onConnect: () => void;
  onDisconnect: () => void;
}

export function MicChrome({ onConnect, onDisconnect }: MicChromeProps) {
  const connection = useSession((s) => s.connection);
  const error = useSession((s) => s.errorMessage);

  const isLive =
    connection === "connected" ||
    connection === "listening" ||
    connection === "thinking" ||
    connection === "speaking";

  const isBusy = connection === "connecting";

  const ringColor =
    connection === "listening"
      ? "var(--brand-yellow)"
      : connection === "speaking"
      ? "var(--brand-purple)"
      : connection === "thinking"
      ? "var(--brand-magenta)"
      : "var(--border-card)";

  const label = isLive
    ? "Tap to end"
    : isBusy
    ? "Connecting…"
    : connection === "error"
    ? "Reconnect"
    : "Tap to start";

  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: "var(--space-3)" }}>
      <button
        onClick={isLive ? onDisconnect : onConnect}
        disabled={isBusy}
        style={{
          width: 88,
          height: 88,
          borderRadius: "50%",
          background: isLive ? "var(--bg-surface-raised)" : "transparent",
          border: `3px solid ${ringColor}`,
          color: "var(--text-primary)",
          fontSize: 32,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          transition: "border-color 200ms, background 200ms",
          cursor: isBusy ? "wait" : "pointer",
          animation: connection === "listening" ? "micPulse 1.4s ease-in-out infinite" : "none",
        }}
      >
        {isLive ? "🎙" : "🎤"}
      </button>
      <div style={{ fontSize: "var(--fs-small)", color: "var(--text-muted)" }}>{label}</div>
      {error && (
        <div
          style={{
            fontSize: "var(--fs-small)",
            color: "var(--severity-critical)",
            maxWidth: 320,
            textAlign: "center",
          }}
        >
          {error}
        </div>
      )}
      <style>{`
        @keyframes micPulse {
          0%, 100% { box-shadow: 0 0 0 0 rgba(252, 226, 5, 0.5); }
          50% { box-shadow: 0 0 0 12px rgba(252, 226, 5, 0); }
        }
      `}</style>
    </div>
  );
}
