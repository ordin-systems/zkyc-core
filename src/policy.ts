import { canonicalJson, sha256Version } from "./canonical.js";
import {
  DomainValidationError,
  canonicalizeAffiliations,
  rejectUnknownKeys,
  requireRecord,
  validateAction,
  validateActionSensitivity,
  validateCapability,
  validateIdentifier,
  type ActionSensitivity,
  type Affiliation,
  type DecisionOutcome,
} from "./domain.js";

export interface PermissionRule {
  readonly action: string;
  readonly actionSensitivity: ActionSensitivity;
  readonly requiredCapabilities: readonly string[];
  readonly requiredAffiliations: readonly Affiliation[];
  readonly effect: DecisionOutcome;
  readonly approverCapability?: string;
}

export interface Policy {
  readonly id: string;
  readonly version: string;
  readonly rules: readonly PermissionRule[];
  readonly defaultEffect: "DENY";
}

export interface CreatePolicyInput {
  readonly id: string;
  readonly rules: readonly {
    readonly action: string;
    readonly actionSensitivity: ActionSensitivity;
    readonly requiredCapabilities: readonly string[];
    readonly requiredAffiliations: readonly Affiliation[];
    readonly effect: DecisionOutcome;
    readonly approverCapability?: string;
  }[];
}

/** Immutable service-configuration boundary for policies trusted by authority transitions. */
export class PolicyRegistry {
  readonly #policies = new Map<string, Policy>();

  constructor(input: { readonly policies: readonly Policy[] }) {
    const record = requireRecord(input, "policy registry input");
    rejectUnknownKeys(record, ["policies"], "policy registry input");
    if (!Array.isArray(record.policies)) {
      throw new DomainValidationError("policy registry policies must be an array");
    }
    for (const [index, value] of record.policies.entries()) {
      const policy = validateExactPolicy(value, `policy registry policies[${index}]`);
      const key = PolicyRegistry.key(policy.id, policy.version);
      if (this.#policies.has(key)) {
        throw new DomainValidationError(
          `policy registry cannot replace duplicate policy ${policy.id}@${policy.version}`,
        );
      }
      this.#policies.set(key, policy);
    }
    Object.freeze(this);
  }

  private static key(id: string, version: string): string {
    return `${id}\u0000${version}`;
  }

  resolve(idValue: unknown, versionValue: unknown): Policy | undefined {
    try {
      const id = validateIdentifier(idValue, "policy id");
      if (typeof versionValue !== "string" || !/^sha256:[0-9a-f]{64}$/.test(versionValue)) {
        return undefined;
      }
      return this.#policies.get(PolicyRegistry.key(id, versionValue));
    } catch {
      return undefined;
    }
  }

  resolveExact(value: unknown): Policy | undefined {
    try {
      const policy = validateExactPolicy(value, "registered policy");
      const registered = this.resolve(policy.id, policy.version);
      return registered !== undefined && canonicalJson(registered) === canonicalJson(policy)
        ? registered
        : undefined;
    } catch {
      return undefined;
    }
  }
}

export function validateExactPolicy(value: unknown, label = "policy"): Policy {
  const record = requireRecord(value, label);
  rejectUnknownKeys(record, ["id", "version", "rules", "defaultEffect"], label);
  const policy = createPolicy({ id: record.id, rules: record.rules as never });
  if (record.version !== policy.version || record.defaultEffect !== policy.defaultEffect) {
    throw new DomainValidationError(
      `${label} must have its exact content-derived version and default effect`,
    );
  }
  return policy;
}

export function createPolicy(input: unknown): Policy {
  const record = requireRecord(input, "policy");
  rejectUnknownKeys(record, ["id", "rules"], "policy");
  const id = validateIdentifier(record.id, "policy.id");
  if (!Array.isArray(record.rules) || record.rules.length === 0) {
    throw new DomainValidationError("policy.rules must be a non-empty array");
  }
  const rules = record.rules.map((value, index): PermissionRule => {
    const rule = requireRecord(value, `policy.rules[${index}]`);
    rejectUnknownKeys(
      rule,
      [
        "action",
        "actionSensitivity",
        "requiredCapabilities",
        "requiredAffiliations",
        "effect",
        "approverCapability",
      ],
      `policy.rules[${index}]`,
    );
    if (!Array.isArray(rule.requiredCapabilities)) {
      throw new DomainValidationError(`policy.rules[${index}].requiredCapabilities must be an array`);
    }
    const requiredCapabilities = rule.requiredCapabilities.map((capability, capabilityIndex) =>
      validateCapability(capability, `policy.rules[${index}].requiredCapabilities[${capabilityIndex}]`),
    );
    if (new Set(requiredCapabilities).size !== requiredCapabilities.length) {
      throw new DomainValidationError(`policy.rules[${index}] capabilities must be unique`);
    }
    requiredCapabilities.sort();
    const requiredAffiliations = canonicalizeAffiliations(
      rule.requiredAffiliations,
      `policy.rules[${index}].requiredAffiliations`,
      { deduplicate: true },
    );
    if (rule.effect !== "ALLOW" && rule.effect !== "DENY" && rule.effect !== "STEP_UP") {
      throw new DomainValidationError(`policy.rules[${index}].effect is unsupported`);
    }
    const effect: DecisionOutcome = rule.effect;
    const base = {
      action: validateAction(rule.action, `policy.rules[${index}].action`),
      actionSensitivity: validateActionSensitivity(
        rule.actionSensitivity,
        `policy.rules[${index}].actionSensitivity`,
      ),
      requiredCapabilities: Object.freeze(requiredCapabilities),
      requiredAffiliations,
      effect,
    };
    if (rule.effect === "STEP_UP") {
      return Object.freeze({
        ...base,
        approverCapability: validateCapability(
          rule.approverCapability,
          `policy.rules[${index}].approverCapability`,
        ),
      });
    }
    if (rule.approverCapability !== undefined) {
      throw new DomainValidationError("only STEP_UP rules may define approverCapability");
    }
    return Object.freeze(base);
  });
  rules.sort((left, right) => left.action < right.action ? -1 : left.action > right.action ? 1 : 0);
  const actions = rules.map((rule) => rule.action);
  if (new Set(actions).size !== actions.length) {
    throw new DomainValidationError("policy contains contradictory or duplicate action rules");
  }
  const version = sha256Version({ id, rules, defaultEffect: "DENY" });
  return Object.freeze({ id, version, rules: Object.freeze(rules), defaultEffect: "DENY" });
}
