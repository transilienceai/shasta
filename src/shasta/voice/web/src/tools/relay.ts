const KNOWN_TOOLS = new Set([
  "list_findings",
  "get_finding",
  "list_top_blockers",
  "get_resource_findings",
  "get_compliance_score",
  "get_multi_framework_score",
  "get_score_trend",
  "get_control_summary",
  "list_scans",
  "get_latest_scan",
  "list_risk_items",
  "get_risk_item",
  "add_risk_item",
  "update_risk",
]);

export interface ToolCallResult {
  output: string;
  parsed: unknown;
  toolName: string;
  latencyMs: number;
}

export async function executeToolCall(toolName: string, argsJson: string): Promise<ToolCallResult> {
  const start = performance.now();
  if (!KNOWN_TOOLS.has(toolName)) {
    const errorPayload = { error: "unknown_tool", tool: toolName };
    return { output: JSON.stringify(errorPayload), parsed: errorPayload, toolName, latencyMs: 0 };
  }
  let args: unknown;
  try {
    args = argsJson ? JSON.parse(argsJson) : {};
  } catch {
    const errorPayload = { error: "invalid_arguments_json", raw: argsJson };
    return { output: JSON.stringify(errorPayload), parsed: errorPayload, toolName, latencyMs: 0 };
  }
  try {
    const resp = await fetch(`/tools/${toolName}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(args),
    });
    if (!resp.ok) {
      const errorPayload = {
        error: "tool_unavailable",
        status: resp.status,
        detail: (await resp.text()).slice(0, 200),
      };
      return { output: JSON.stringify(errorPayload), parsed: errorPayload, toolName, latencyMs: performance.now() - start };
    }
    const parsed = await resp.json();
    return { output: JSON.stringify(parsed), parsed, toolName, latencyMs: performance.now() - start };
  } catch (err) {
    const errorPayload = { error: "tool_unavailable", detail: err instanceof Error ? err.message : String(err) };
    return { output: JSON.stringify(errorPayload), parsed: errorPayload, toolName, latencyMs: performance.now() - start };
  }
}
