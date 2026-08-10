import { ActionSensitivity, type CreatePolicyInput } from "@ordin/zkyc-core-reference";

const operatorMember = { organizationId: "organization:reference", role: "member" } as const;
const onboardingAgent = {
  organizationId: "organization:ordin-reference",
  role: "automation-agent",
} as const;

/** Fixed policies used only by the checked-in local reference UIs. */
const catalog: CreatePolicyInput[] = [
  {
    id: "policy:reference-allow",
    rules: [{
      action: "records:read",
      actionSensitivity: ActionSensitivity.ROUTINE,
      requiredCapabilities: ["records:read"],
      requiredAffiliations: [operatorMember],
      effect: "ALLOW",
    }],
  },
  {
    id: "policy:reference-deny",
    rules: [{
      action: "records:delete",
      actionSensitivity: ActionSensitivity.CRITICAL,
      requiredCapabilities: ["records:delete"],
      requiredAffiliations: [operatorMember],
      effect: "DENY",
    }],
  },
  {
    id: "policy:reference-step-up",
    rules: [{
      action: "records:export",
      actionSensitivity: ActionSensitivity.SENSITIVE,
      requiredCapabilities: ["records:export"],
      requiredAffiliations: [operatorMember],
      effect: "STEP_UP",
      approverCapability: "approval:records-export",
    }],
  },
  {
    id: "policy:reference-delegated-allow",
    rules: [{
      action: "records:read",
      actionSensitivity: ActionSensitivity.ROUTINE,
      requiredCapabilities: ["records:read"],
      requiredAffiliations: [],
      effect: "ALLOW",
    }],
  },
  {
    id: "policy:zkya-direct-read",
    rules: [{
      action: "records:read",
      actionSensitivity: ActionSensitivity.ROUTINE,
      requiredCapabilities: ["records:read"],
      requiredAffiliations: [onboardingAgent],
      effect: "ALLOW",
    }],
  },
  {
    id: "policy:zkya-delegated-read",
    rules: [{
      action: "records:read",
      actionSensitivity: ActionSensitivity.ROUTINE,
      requiredCapabilities: ["records:read"],
      requiredAffiliations: [],
      effect: "ALLOW",
    }],
  },
  {
    id: "policy:zkya-sensitive-export",
    rules: [{
      action: "records:export",
      actionSensitivity: ActionSensitivity.SENSITIVE,
      requiredCapabilities: ["records:export"],
      requiredAffiliations: [],
      effect: "STEP_UP",
      approverCapability: "approval:records-export",
    }],
  },
  {
    id: "policy:zkya-action-scope-boundary",
    rules: [{
      action: "records:write",
      actionSensitivity: ActionSensitivity.ROUTINE,
      requiredCapabilities: ["records:write"],
      requiredAffiliations: [],
      effect: "ALLOW",
    }],
  },
  {
    id: "policy:zkya-resource-scope-boundary",
    rules: [{
      action: "records:read",
      actionSensitivity: ActionSensitivity.ROUTINE,
      requiredCapabilities: ["records:read"],
      requiredAffiliations: [],
      effect: "ALLOW",
    }],
  },
];

export const localReferencePolicyCatalog: readonly CreatePolicyInput[] = Object.freeze(catalog);
