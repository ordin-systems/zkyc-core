import type {
  AccessDecision,
  OnboardingView,
  PolicyInput,
  SignedReceipt,
  StepUpRequest,
  ZkycReferenceClient,
} from "@ordin/zkyc-sdk-reference";

export type OnboardingClient = Pick<
  ZkycReferenceClient,
  | "issueCredential"
  | "revokeCredential"
  | "issueDelegation"
  | "revokeDelegation"
  | "evaluate"
  | "createStepUpRequest"
  | "resolveStepUpRequest"
  | "consumeReceipt"
  | "getOnboardingView"
>;

export interface ScenarioExecution {
  readonly logId: string;
  readonly decision: AccessDecision;
  readonly receipt?: SignedReceipt;
  readonly stepUpRequest?: StepUpRequest;
}

export interface ReferenceScenario {
  readonly id: string;
  readonly index: string;
  readonly label: string;
  readonly mode: "DIRECT" | "DELEGATED";
  readonly expected: "ALLOW" | "STEP_UP" | "DENY";
  readonly summary: string;
}

export const scenarios: readonly ReferenceScenario[] = [
  {
    id: "direct-allow",
    index: "01",
    label: "Direct agent allowance",
    mode: "DIRECT",
    expected: "ALLOW",
    summary: "An independently credentialed agent receives a signed v2 receipt with durable consumption and latest-attempt state.",
  },
  {
    id: "delegated-allow",
    index: "02",
    label: "Delegated organization scope",
    mode: "DELEGATED",
    expected: "ALLOW",
    summary: "An AGENT acts under an exact, one-hop ORGANIZATION grant with attenuated scope.",
  },
  {
    id: "step-up",
    index: "03",
    label: "Human step-up boundary",
    mode: "DIRECT",
    expected: "STEP_UP",
    summary: "A sensitive export remains pending until a freshly credentialed HUMAN resolves it.",
  },
  {
    id: "action-scope-deny",
    index: "04",
    label: "Action scope mismatch",
    mode: "DIRECT",
    expected: "DENY",
    summary: "The requested action exceeds the credential's exact action boundary and fails closed.",
  },
  {
    id: "resource-scope-deny",
    index: "05",
    label: "Resource scope mismatch",
    mode: "DIRECT",
    expected: "DENY",
    summary: "The requested resource is outside the credential's exact resource boundary.",
  },
  {
    id: "revoked-delegation",
    index: "06",
    label: "Revoked delegation",
    mode: "DELEGATED",
    expected: "DENY",
    summary: "A known delegation is revoked before evaluation and remains visibly ineligible.",
  },
] as const;

function future(minutes: number): string {
  return new Date(Date.now() + minutes * 60_000).toISOString();
}

const agentAffiliation = {
  organizationId: "organization:ordin-reference",
  role: "automation-agent",
} as const;

const reviewAffiliation = {
  organizationId: "organization:research-reference",
  role: "review-participant",
} as const;

function singleRulePolicy(input: {
  readonly id: string;
  readonly action: string;
  readonly sensitivity: "ROUTINE" | "SENSITIVE" | "CRITICAL";
  readonly capability: string;
  readonly effect: "ALLOW" | "DENY" | "STEP_UP";
  readonly requiredAffiliations?: readonly typeof agentAffiliation[];
  readonly approverCapability?: string;
}): PolicyInput {
  return {
    id: input.id,
    rules: [{
      action: input.action,
      actionSensitivity: input.sensitivity,
      requiredCapabilities: [input.capability],
      requiredAffiliations: input.requiredAffiliations ?? [],
      effect: input.effect,
      ...(input.approverCapability === undefined
        ? {}
        : { approverCapability: input.approverCapability }),
    }],
  };
}

async function directAllow(client: OnboardingClient): Promise<ScenarioExecution> {
  const principal = {
    id: "agent:reference-direct-reader",
    type: "AGENT",
    affiliations: [agentAffiliation, reviewAffiliation],
  } as const;
  const action = "records:read";
  const resourceId = "record:reference-alpha";
  const policy = singleRulePolicy({
    id: "policy:zkya-direct-read",
    action,
    sensitivity: "ROUTINE",
    capability: action,
    effect: "ALLOW",
    requiredAffiliations: [agentAffiliation],
  });
  const { credential } = await client.issueCredential({
    principal,
    capabilities: [action],
    allowedActions: [action],
    allowedResourceIds: [resourceId],
    expiresAt: future(60),
  });
  return client.evaluate({
    authorityMode: "DIRECT",
    principal,
    credential,
    action,
    resourceId,
    actionContext: { purpose: "local-onboarding-reference", fields: ["status"] },
    policy,
    issueReceipt: true,
    receiptExpiresAt: future(15),
  });
}

interface DelegatedSetup {
  readonly grantor: {
    readonly id: string;
    readonly type: "ORGANIZATION";
    readonly affiliations: readonly [];
  };
  readonly delegate: {
    readonly id: string;
    readonly type: "AGENT";
    readonly affiliations: readonly [typeof agentAffiliation];
  };
  readonly policy: PolicyInput;
  readonly grantorCredential: Awaited<ReturnType<OnboardingClient["issueCredential"]>>["credential"];
  readonly delegateIdentityCredential: Awaited<ReturnType<OnboardingClient["issueCredential"]>>["credential"];
  readonly delegation: Awaited<ReturnType<OnboardingClient["issueDelegation"]>>["delegation"];
}

async function delegatedSetup(client: OnboardingClient): Promise<DelegatedSetup> {
  const grantor = {
    id: "organization:reference-grantor",
    type: "ORGANIZATION",
    affiliations: [],
  } as const;
  const delegate = {
    id: "agent:reference-delegate",
    type: "AGENT",
    affiliations: [agentAffiliation],
  } as const;
  const policy = singleRulePolicy({
    id: "policy:zkya-delegated-read",
    action: "records:read",
    sensitivity: "ROUTINE",
    capability: "records:read",
    effect: "ALLOW",
  });
  const { credential: grantorCredential } = await client.issueCredential({
    principal: grantor,
    capabilities: ["records:read", "records:write"],
    allowedActions: ["records:read", "records:write"],
    allowedResourceIds: ["dataset:reference-alpha", "dataset:reference-beta"],
    expiresAt: future(60),
  });
  const { credential: delegateIdentityCredential } = await client.issueCredential({
    principal: delegate,
    capabilities: ["identity:present"],
    allowedActions: ["identity:present"],
    allowedResourceIds: [delegate.id],
    expiresAt: future(60),
  });
  const { delegation } = await client.issueDelegation({
    grantor,
    grantorCredential,
    delegate,
    policy,
    capabilities: ["records:read"],
    allowedActions: ["records:read"],
    allowedResourceIds: ["dataset:reference-alpha"],
    expiresAt: future(30),
  });
  return { grantor, delegate, policy, grantorCredential, delegateIdentityCredential, delegation };
}

async function delegatedAllow(
  client: OnboardingClient,
  revokeFirst: boolean,
): Promise<ScenarioExecution> {
  const setup = await delegatedSetup(client);
  if (revokeFirst) {
    await client.revokeDelegation(setup.delegation.id, { reason: "reference-scenario-revocation" });
  }
  return client.evaluate({
    authorityMode: "DELEGATED",
    principal: setup.delegate,
    delegateIdentityCredential: setup.delegateIdentityCredential,
    grantorCredential: setup.grantorCredential,
    delegation: setup.delegation,
    action: "records:read",
    resourceId: "dataset:reference-alpha",
    actionContext: { purpose: "delegated-local-reference" },
    policy: setup.policy,
    issueReceipt: !revokeFirst,
    ...(revokeFirst ? {} : { receiptExpiresAt: future(15) }),
  });
}

async function stepUp(client: OnboardingClient): Promise<ScenarioExecution> {
  const principal = {
    id: "agent:reference-exporter",
    type: "AGENT",
    affiliations: [],
  } as const;
  const action = "records:export";
  const resourceId = "dataset:reference-sensitive";
  const policy = singleRulePolicy({
    id: "policy:zkya-sensitive-export",
    action,
    sensitivity: "SENSITIVE",
    capability: action,
    effect: "STEP_UP",
    approverCapability: "approval:records-export",
  });
  const { credential } = await client.issueCredential({
    principal,
    capabilities: [action],
    allowedActions: [action],
    allowedResourceIds: [resourceId],
    expiresAt: future(60),
  });
  const evaluated = await client.evaluate({
    authorityMode: "DIRECT",
    principal,
    credential,
    action,
    resourceId,
    actionContext: { destination: "local-reviewer", rows: 24 },
    policy,
    issueReceipt: false,
  });
  const { request } = await client.createStepUpRequest({
    decisionLogId: evaluated.logId,
    expiresAt: future(15),
  });
  return { ...evaluated, stepUpRequest: request };
}

async function scopeDeny(
  client: OnboardingClient,
  axis: "action" | "resource",
): Promise<ScenarioExecution> {
  const principal = {
    id: `agent:reference-${axis}-boundary`,
    type: "AGENT",
    affiliations: [agentAffiliation],
  } as const;
  const requestedAction = axis === "action" ? "records:write" : "records:read";
  const requestedResource = axis === "resource"
    ? "record:reference-outside"
    : "record:reference-alpha";
  const { credential } = await client.issueCredential({
    principal,
    capabilities: [requestedAction],
    allowedActions: ["records:read"],
    allowedResourceIds: ["record:reference-alpha"],
    expiresAt: future(60),
  });
  return client.evaluate({
    authorityMode: "DIRECT",
    principal,
    credential,
    action: requestedAction,
    resourceId: requestedResource,
    actionContext: { purpose: "fail-closed-scope-demonstration" },
    policy: singleRulePolicy({
      id: `policy:zkya-${axis}-scope-boundary`,
      action: requestedAction,
      sensitivity: "ROUTINE",
      capability: requestedAction,
      effect: "ALLOW",
    }),
    issueReceipt: false,
  });
}

export async function executeScenario(
  scenarioId: string,
  client: OnboardingClient,
): Promise<ScenarioExecution> {
  switch (scenarioId) {
    case "direct-allow":
      return directAllow(client);
    case "delegated-allow":
      return delegatedAllow(client, false);
    case "step-up":
      return stepUp(client);
    case "action-scope-deny":
      return scopeDeny(client, "action");
    case "resource-scope-deny":
      return scopeDeny(client, "resource");
    case "revoked-delegation":
      return delegatedAllow(client, true);
    default:
      throw new Error("unknown reference scenario");
  }
}

export async function refreshOnboardingView(
  client: OnboardingClient,
  logId: string,
): Promise<OnboardingView> {
  return client.getOnboardingView(logId);
}
