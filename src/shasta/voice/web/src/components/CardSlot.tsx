import { AnimatePresence } from "framer-motion";
import { useSession } from "../state/session";
import { ActionToast } from "./cards/ActionToast";
import { ComplianceScore } from "./cards/ComplianceScore";
import { ControlSummary } from "./cards/ControlSummary";
import { FindingDetail } from "./cards/FindingDetail";
import { FindingsList } from "./cards/FindingsList";
import { MultiFrameworkScore } from "./cards/MultiFrameworkScore";
import { RiskDetail } from "./cards/RiskDetail";
import { RiskList } from "./cards/RiskList";

export function CardSlot() {
  const card = useSession((s) => s.activeCard);
  return (
    <div style={{ height: "100%", display: "flex", alignItems: "flex-start" }}>
      <div style={{ width: "100%" }}>
        <AnimatePresence mode="wait">
          {card.kind === "findings_list" && <FindingsList key="findings_list" findings={card.data} />}
          {card.kind === "finding_detail" && <FindingDetail key={`finding-${card.data.id}`} finding={card.data} />}
          {card.kind === "compliance_score" && <ComplianceScore key={`score-${card.data.framework}`} score={card.data} />}
          {card.kind === "multi_framework" && <MultiFrameworkScore key="multi" data={card.data} />}
          {card.kind === "control_summary" && <ControlSummary key="controls" controls={card.data} />}
          {card.kind === "risk_list" && <RiskList key="risk_list" risks={card.data} />}
          {card.kind === "risk_detail" && <RiskDetail key={`risk-${card.data.risk_id}`} risk={card.data} />}
          {card.kind === "action" && <ActionToast key={`action-${(card.data as any).timestamp ?? Date.now()}`} action={card.data as any} />}
          {card.kind === "none" && (
            <div key="empty" style={{ color: "var(--text-subtle)", fontSize: "var(--fs-small)", padding: "var(--space-5)", textAlign: "center" }}>
              Ask about findings, scores, controls, or risks to populate this panel.
            </div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}
