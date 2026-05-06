import { motion } from "framer-motion";
import type { ActionResult } from "../../tools/types";

export function ActionToast({ action }: { action: ActionResult }) {
  const ok = action.success;
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -8 }}
      transition={{ duration: 0.2 }}
      style={{
        background: "var(--bg-surface)",
        border: `1px solid ${ok ? "var(--brand-yellow)" : "var(--severity-critical)"}`,
        borderRadius: "var(--radius-md)",
        padding: "var(--space-5)",
        display: "flex",
        alignItems: "center",
        gap: "var(--space-4)",
      }}
    >
      <div
        style={{
          fontSize: 28,
          color: ok ? "var(--brand-yellow)" : "var(--severity-critical)",
        }}
      >
        {ok ? "✓" : "✗"}
      </div>
      <div>
        <div style={{ fontWeight: 700 }}>{action.message}</div>
        {action.new_status && action.timestamp && (
          <div style={{ fontSize: "var(--fs-small)", color: "var(--text-muted)" }}>
            New status: {action.new_status} · {new Date(action.timestamp).toLocaleTimeString()}
          </div>
        )}
      </div>
    </motion.div>
  );
}
