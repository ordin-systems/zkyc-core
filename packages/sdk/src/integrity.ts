import { InvalidProtocolResponse } from "./validation.js";
import type {
  Affiliation,
  AuthorityScope,
  CapabilityDelegation,
  PolicyInput,
  PolicyRule,
} from "./index.js";

function normalize(value: unknown): unknown {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new InvalidProtocolResponse();
    return value;
  }
  if (Array.isArray(value)) return value.map(normalize);
  if (typeof value === "object") {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) throw new InvalidProtocolResponse();
    const output: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      const child = (value as Record<string, unknown>)[key];
      if (child === undefined) throw new InvalidProtocolResponse();
      output[key] = normalize(child);
    }
    return output;
  }
  throw new InvalidProtocolResponse();
}

function canonicalJson(value: unknown): string {
  return JSON.stringify(normalize(value));
}

async function sha256Version(value: unknown): Promise<string> {
  const cryptoValue = Reflect.get(globalThis, "crypto") as Crypto | undefined;
  if (cryptoValue?.subtle === undefined) throw new InvalidProtocolResponse();
  try {
    const digest = await cryptoValue.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(canonicalJson(value)),
    );
    const hex = [...new Uint8Array(digest)]
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("");
    return `sha256:${hex}`;
  } catch (error) {
    if (error instanceof InvalidProtocolResponse) throw error;
    throw new InvalidProtocolResponse();
  }
}

function compare(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function canonicalStrings(values: readonly string[]): readonly string[] {
  return [...values].sort(compare);
}

function canonicalAffiliations(values: readonly Affiliation[]): readonly Affiliation[] {
  const keyed = new Map<string, Affiliation>();
  for (const value of values) keyed.set(`${value.organizationId}\u0000${value.role}`, value);
  return [...keyed.values()].sort((left, right) =>
    compare(left.organizationId, right.organizationId) || compare(left.role, right.role)
  );
}

function canonicalRule(rule: PolicyRule): PolicyRule {
  return {
    action: rule.action,
    actionSensitivity: rule.actionSensitivity,
    requiredCapabilities: canonicalStrings(rule.requiredCapabilities),
    requiredAffiliations: canonicalAffiliations(rule.requiredAffiliations),
    effect: rule.effect,
    ...(rule.approverCapability === undefined
      ? {}
      : { approverCapability: rule.approverCapability }),
  };
}

export interface CanonicalPolicy {
  readonly id: string;
  readonly version: string;
  readonly rules: readonly PolicyRule[];
  readonly defaultEffect: "DENY";
}

export async function canonicalPolicy(policy: PolicyInput): Promise<CanonicalPolicy> {
  const rules = policy.rules.map(canonicalRule).sort((left, right) => compare(left.action, right.action));
  const version = await sha256Version({ id: policy.id, rules, defaultEffect: "DENY" });
  return { id: policy.id, version, rules, defaultEffect: "DENY" };
}

export async function computeScopeHash(scope: AuthorityScope): Promise<string> {
  return sha256Version({
    domain: "zkyc-scope",
    version: 1,
    capabilities: canonicalStrings(scope.capabilities),
    allowedActions: canonicalStrings(scope.allowedActions),
    allowedResourceIds: canonicalStrings(scope.allowedResourceIds),
  });
}

export async function computeContextHash(context: Readonly<Record<string, unknown>>): Promise<string> {
  return sha256Version(context);
}

export async function computeDelegationBindingHash(
  delegation: CapabilityDelegation,
): Promise<string> {
  return sha256Version({
    domain: "zkyc-delegation-binding",
    version: 1,
    delegation: {
      version: delegation.version,
      id: delegation.id,
      issuerId: delegation.issuerId,
      grantorCredentialId: delegation.grantorCredentialId,
      grantorId: delegation.grantorId,
      grantorType: delegation.grantorType,
      delegateId: delegation.delegateId,
      delegateType: delegation.delegateType,
      policyId: delegation.policyId,
      policyVersion: delegation.policyVersion,
      capabilities: delegation.capabilities,
      allowedActions: delegation.allowedActions,
      allowedResourceIds: delegation.allowedResourceIds,
      issuedAt: delegation.issuedAt,
      expiresAt: delegation.expiresAt,
      scopeHash: delegation.scopeHash,
    },
  });
}
