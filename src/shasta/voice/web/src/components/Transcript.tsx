import { useEffect, useRef } from "react";
import { useSession } from "../state/session";

export function Transcript() {
  const transcript = useSession((s) => s.transcript);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [transcript]);

  return (
    <div
      style={{
        height: "100%",
        background: "var(--bg-surface)",
        border: "1px solid var(--border-subtle)",
        borderRadius: "var(--radius-md)",
        padding: "var(--space-4)",
        overflowY: "auto",
        display: "flex",
        flexDirection: "column",
        gap: "var(--space-3)",
      }}
      ref={scrollRef}
    >
      {transcript.length === 0 && (
        <div style={{ color: "var(--text-subtle)", fontSize: "var(--fs-small)" }}>
          Transcript will appear here as you speak.
        </div>
      )}
      {transcript.map((line) => (
        <div key={line.id}>
          <div
            style={{
              fontSize: "var(--fs-small)",
              fontWeight: 700,
              textTransform: "uppercase",
              letterSpacing: "0.04em",
              color:
                line.who === "user" ? "var(--brand-yellow)" : "var(--text-muted)",
              marginBottom: 2,
            }}
          >
            {line.who === "user" ? "you" : "assistant"}
          </div>
          <div
            style={{
              color: line.partial ? "var(--text-muted)" : "var(--text-primary)",
              lineHeight: 1.5,
            }}
          >
            {line.text}
            {line.partial && <span style={{ opacity: 0.5 }}>…</span>}
          </div>
        </div>
      ))}
    </div>
  );
}
