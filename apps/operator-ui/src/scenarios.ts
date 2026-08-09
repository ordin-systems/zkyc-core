import type { ActionSensitivity, PolicyInput, Principal } from "@ordin/zkyc-sdk-reference";

export interface ReferenceScenario {
  readonly id: string;
  readonly label: string;
  readonly summary: string;
  readonly principal: Principal;
  readonly capabilities: readonly string[];
  readonly action: string;
  readonly sensitivity: ActionSensitivity;
  readonly resourceId: string;
  readonly actionContext: Readonly<Record<string, unknown>>;
  readonly policy: PolicyInput;
  readonly outcome: "ALLOW" | "DENY" | "STEP_UP";
}

const member = { organizationId: "organization:reference", role: "member" } as const;

export const scenarios: readonly ReferenceScenario[] = [
  {
    id: "allow",
    label: "Routine read",
    summary: "A capability-bound routine read receives ALLOW and a one-time receipt.",
    principal: { id: "principal:reference-reader", affiliations: [member] },
    capabilities: ["records:read"],
    action: "records:read",
    sensitivity: "ROUTINE",
    resourceId: "record:reference-7",
    actionContext: { fields: ["status"], purpose: "review" },
    outcome: "ALLOW",
    policy: {
      id: "policy:reference-allow",
      rules: [{
        action: "records:read",
        actionSensitivity: "ROUTINE",
        requiredCapabilities: ["records:read"],
        requiredAffiliations: [member],
        effect: "ALLOW",
      }],
    },
  },
  {
    id: "deny",
    label: "Critical delete",
    summary: "A policy-level prohibition returns DENY and never produces a receipt.",
    principal: { id: "principal:reference-delete", affiliations: [member] },
    capabilities: ["records:delete"],
    action: "records:delete",
    sensitivity: "CRITICAL",
    resourceId: "record:reference-7",
    actionContext: { purpose: "cleanup" },
    outcome: "DENY",
    policy: {
      id: "policy:reference-deny",
      rules: [{
        action: "records:delete",
        actionSensitivity: "CRITICAL",
        requiredCapabilities: ["records:delete"],
        requiredAffiliations: [member],
        effect: "DENY",
      }],
    },
  },
  {
    id: "step-up",
    label: "Sensitive export",
    summary: "A sensitive export pauses for a bound human approval or rejection.",
    principal: { id: "principal:reference-exporter", affiliations: [member] },
    capabilities: ["records:export"],
    action: "records:export",
    sensitivity: "SENSITIVE",
    resourceId: "dataset:reference-7",
    actionContext: { destination: "reviewer", rows: 25 },
    outcome: "STEP_UP",
    policy: {
      id: "policy:reference-step-up",
      rules: [{
        action: "records:export",
        actionSensitivity: "SENSITIVE",
        requiredCapabilities: ["records:export"],
        requiredAffiliations: [member],
        effect: "STEP_UP",
        approverCapability: "approval:records-export",
      }],
    },
  },
];
