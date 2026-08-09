import { canonicalJson, sha256Version } from "./canonical.js";
import {
  REASON_CODES,
  ActionSensitivity,
  createPrincipal,
  rejectUnknownKeys,
  requireRecord,
  validateAction,
  validateIdentifier,
  validateTimestamp,
  type DecisionOutcome,
  type Principal,
  type ReasonCode,
  type UnverifiedMetadata,
} from "./domain.js";
import { CredentialAuthority, type Credential } from "./credentials.js";
import { createPolicy, type Policy } from "./policy.js";

export interface AccessDecision {
  readonly outcome: DecisionOutcome;
  readonly reasonCode: ReasonCode;
  readonly subjectId: string;
  readonly action: string;
  readonly actionSensitivity: ActionSensitivity;
  readonly resourceId: string;
  readonly contextHash: string;
  readonly policyId: string;
  readonly policyVersion: string;
  readonly credentialId?: string;
  readonly decidedAt: string;
  readonly requiredApproverCapability?: string;
  readonly unverifiedMetadata?: UnverifiedMetadata;
}

export interface AccessEvaluationInput {
  readonly principal: Principal;
  readonly credential: Credential | null;
  readonly action: string;
  readonly resourceId: string;
  readonly actionContext: Readonly<Record<string, unknown>>;
  readonly policy: Policy;
  readonly at: string;
  readonly credentialAuthority: CredentialAuthority;
}

function invalidDecision(at?: unknown): AccessDecision {
  let decidedAt = "1970-01-01T00:00:00.000Z";
  try {
    decidedAt = validateTimestamp(at, "decision time");
  } catch {
    // The fail-closed decision intentionally uses a fixed sentinel time.
  }
  return Object.freeze({
    outcome: "DENY",
    reasonCode: "INVALID_INPUT",
    subjectId: "unknown",
    action: "unknown",
    actionSensitivity: ActionSensitivity.ROUTINE,
    resourceId: "unknown",
    contextHash: sha256Version({}),
    policyId: "unknown",
    policyVersion: "unknown",
    decidedAt,
  });
}

export function evaluateAccess(value: unknown): AccessDecision {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return invalidDecision();
  const input = value as Partial<AccessEvaluationInput>;
  let principal: Principal;
  let action: string;
  let resourceId: string;
  let contextHash: string;
  let policy: Policy;
  let at: string;
  try {
    rejectUnknownKeys(
      requireRecord(value, "access evaluation"),
      [
        "principal",
        "credential",
        "action",
        "resourceId",
        "actionContext",
        "policy",
        "at",
        "credentialAuthority",
      ],
      "access evaluation",
    );
    principal = createPrincipal(input.principal);
    action = validateAction(input.action, "action");
    resourceId = validateIdentifier(input.resourceId, "resourceId");
    contextHash = sha256Version(requireRecord(input.actionContext, "actionContext"));
    at = validateTimestamp(input.at, "decision time");
    if (typeof input.policy !== "object" || input.policy === null) return invalidDecision(at);
    policy = createPolicy({ id: input.policy.id, rules: input.policy.rules });
    if (policy.version !== input.policy.version || input.policy.defaultEffect !== "DENY") {
      return invalidDecision(at);
    }
    if (!(input.credentialAuthority instanceof CredentialAuthority)) return invalidDecision(at);
  } catch {
    return invalidDecision(input.at);
  }

  const rule = policy.rules.find((candidate) => candidate.action === action);
  const base = {
    subjectId: principal.id,
    action,
    actionSensitivity: rule?.actionSensitivity ?? ActionSensitivity.ROUTINE,
    resourceId,
    contextHash,
    policyId: policy.id,
    policyVersion: policy.version,
    decidedAt: at,
  };
  const deny = (reasonCode: ReasonCode, credential?: Credential): AccessDecision =>
    Object.freeze({
      outcome: "DENY",
      reasonCode,
      ...base,
      ...(credential === undefined ? {} : { credentialId: credential.id }),
      ...(credential?.unverifiedMetadata === undefined
        ? {}
        : { unverifiedMetadata: credential.unverifiedMetadata }),
    });

  if (input.credential === null || input.credential === undefined) return deny("CREDENTIAL_MISSING");
  const credential = input.credential;
  if (typeof credential !== "object" || credential === null) return deny("CREDENTIAL_MALFORMED");
  if (credential.principalId !== principal.id) return deny("CREDENTIAL_SUBJECT_MISMATCH", credential);

  const status = input.credentialAuthority.checkCredential(credential, at);
  if (!status.valid) {
    const mapped = REASON_CODES.find((reason) => reason === status.code);
    return deny(mapped ?? "CREDENTIAL_MALFORMED", credential);
  }
  if (canonicalJson(credential.affiliations) !== canonicalJson(principal.affiliations)) {
    return deny("CREDENTIAL_SUBJECT_MISMATCH", credential);
  }

  if (rule === undefined) return deny("ACTION_NOT_PERMITTED", credential);
  if (rule.effect === "DENY") return deny("POLICY_DENY", credential);
  const granted = new Set(credential.capabilities);
  if (!rule.requiredCapabilities.every((capability) => granted.has(capability))) {
    return deny("INSUFFICIENT_CAPABILITY", credential);
  }
  const affiliationKeys = new Set(
    credential.affiliations.map((affiliation) => `${affiliation.organizationId}\u0000${affiliation.role}`),
  );
  if (
    !rule.requiredAffiliations.every((affiliation) =>
      affiliationKeys.has(`${affiliation.organizationId}\u0000${affiliation.role}`),
    )
  ) {
    return deny("AFFILIATION_REQUIRED", credential);
  }

  const metadata = credential.unverifiedMetadata;
  if (rule.effect === "ALLOW") {
    return Object.freeze({
      outcome: "ALLOW",
      reasonCode: "POLICY_ALLOW",
      ...base,
      credentialId: credential.id,
      ...(metadata === undefined ? {} : { unverifiedMetadata: metadata }),
    });
  }
  return Object.freeze({
    outcome: "STEP_UP",
    reasonCode: "HUMAN_APPROVAL_REQUIRED",
    ...base,
    credentialId: credential.id,
    requiredApproverCapability: rule.approverCapability as string,
    ...(metadata === undefined ? {} : { unverifiedMetadata: metadata }),
  });
}
