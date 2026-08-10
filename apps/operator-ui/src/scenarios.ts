import type { ActionSensitivity, PolicyInput, Principal } from "@ordin/zkyc-sdk-reference";

export interface ReferenceScenario {
  readonly id: string;
  readonly label: string;
  readonly summary: string;
  readonly principal: Principal;
  readonly authorityMode: "DIRECT" | "DELEGATED";
  readonly capabilities: readonly string[];
  readonly allowedActions: readonly string[];
  readonly allowedResourceIds: readonly string[];
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
    principal: { id: "principal:reference-reader", type: "AGENT", affiliations: [member] },
    authorityMode: "DIRECT",
    capabilities: ["records:read"],
    allowedActions: ["records:read"],
    allowedResourceIds: ["record:reference-7"],
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
    principal: { id: "principal:reference-delete", type: "AGENT", affiliations: [member] },
    authorityMode: "DIRECT",
    capabilities: ["records:delete"],
    allowedActions: ["records:delete"],
    allowedResourceIds: ["record:reference-7"],
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
    principal: { id: "principal:reference-exporter", type: "AGENT", affiliations: [member] },
    authorityMode: "DIRECT",
    capabilities: ["records:export"],
    allowedActions: ["records:export"],
    allowedResourceIds: ["dataset:reference-7"],
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
  {
    id: "delegated",
    label: "Delegated routine read",
    summary: "An AGENT acts under an exact one-hop ORGANIZATION grant without inheriting affiliations.",
    principal: { id: "principal:reference-delegate", type: "AGENT", affiliations: [member] },
    authorityMode: "DELEGATED",
    capabilities: ["records:read"],
    allowedActions: ["records:read"],
    allowedResourceIds: ["record:reference-delegated"],
    action: "records:read",
    sensitivity: "ROUTINE",
    resourceId: "record:reference-delegated",
    actionContext: { purpose: "delegated-review" },
    outcome: "ALLOW",
    policy: {
      id: "policy:reference-delegated-allow",
      rules: [{
        action: "records:read",
        actionSensitivity: "ROUTINE",
        requiredCapabilities: ["records:read"],
        requiredAffiliations: [],
        effect: "ALLOW",
      }],
    },
  },
];
