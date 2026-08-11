import {
  InvalidProtocolResponse,
  validateAuthorizationConsumeResponse,
  validateCredentialResponse,
  validateDecisionLogResponse,
  validateDelegationResponse,
  validateEvaluationResponse,
  validateHealthResponse,
  validateOnboardingView,
  validateReceiptConsumeResponse,
  validateResolutionResponse,
  validateRevocationResponse,
  validateStepUpRequestResponse,
} from "./validation.js";
import {
  canonicalPolicy,
  computeContextHash,
  computeDelegationBindingHash,
  computeScopeHash,
  type CanonicalPolicy,
} from "./integrity.js";

export type FetchLike = (input: RequestInfo | URL, init?: RequestInit) => Response | Promise<Response>;

export type PrincipalType = "HUMAN" | "ORGANIZATION" | "AGENT";
export type AuthorityMode = "DIRECT" | "DELEGATED";
export type ActionSensitivity = "ROUTINE" | "SENSITIVE" | "CRITICAL";
export type DecisionOutcome = "ALLOW" | "DENY" | "STEP_UP";
export type ReasonCode =
  | "POLICY_ALLOW"
  | "POLICY_DENY"
  | "HUMAN_APPROVAL_REQUIRED"
  | "INVALID_INPUT"
  | "CREDENTIAL_MISSING"
  | "CREDENTIAL_MALFORMED"
  | "CREDENTIAL_UNKNOWN"
  | "CREDENTIAL_NOT_YET_VALID"
  | "CREDENTIAL_EXPIRED"
  | "CREDENTIAL_REVOKED"
  | "CREDENTIAL_SUBJECT_MISMATCH"
  | "ACTION_OUTSIDE_CREDENTIAL_SCOPE"
  | "RESOURCE_OUTSIDE_CREDENTIAL_SCOPE"
  | "DELEGATION_MALFORMED"
  | "DELEGATION_UNKNOWN"
  | "DELEGATION_NOT_YET_VALID"
  | "DELEGATION_EXPIRED"
  | "DELEGATION_REVOKED"
  | "DELEGATION_POLICY_MISMATCH"
  | "DELEGATION_GRANTOR_CREDENTIAL_INVALID"
  | "DELEGATION_GRANTOR_MISMATCH"
  | "DELEGATION_DELEGATE_MISMATCH"
  | "DELEGATION_IDENTITIES_NOT_DISTINCT"
  | "ACTION_OUTSIDE_DELEGATION_SCOPE"
  | "RESOURCE_OUTSIDE_DELEGATION_SCOPE"
  | "INSUFFICIENT_DELEGATED_CAPABILITY"
  | "INSUFFICIENT_CAPABILITY"
  | "AFFILIATION_REQUIRED"
  | "ACTION_NOT_PERMITTED";

export interface Affiliation {
  readonly organizationId: string;
  readonly role: string;
}

export interface Principal {
  readonly id: string;
  readonly type: PrincipalType;
  readonly affiliations: readonly Affiliation[];
}

export interface UnverifiedMetadata {
  readonly zkPassProofId?: string;
  readonly contextualProofIds?: readonly string[];
}

export interface AuthorityScope {
  readonly capabilities: readonly string[];
  readonly allowedActions: readonly string[];
  readonly allowedResourceIds: readonly string[];
}

export interface Credential extends AuthorityScope {
  readonly version: 2;
  readonly id: string;
  readonly issuerId: string;
  readonly principalId: string;
  readonly principalType: PrincipalType;
  readonly affiliations: readonly Affiliation[];
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly scopeHash: string;
  readonly unverifiedMetadata?: UnverifiedMetadata;
}

export interface CapabilityDelegation extends AuthorityScope {
  readonly version: 1;
  readonly id: string;
  readonly issuerId: string;
  readonly grantorCredentialId: string;
  readonly grantorId: string;
  readonly grantorType: PrincipalType;
  readonly delegateId: string;
  readonly delegateType: PrincipalType;
  readonly policyId: string;
  readonly policyVersion: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly scopeHash: string;
  readonly delegationBindingHash: string;
}

export interface PolicyRule {
  readonly action: string;
  readonly actionSensitivity: ActionSensitivity;
  readonly requiredCapabilities: readonly string[];
  readonly requiredAffiliations: readonly Affiliation[];
  readonly effect: DecisionOutcome;
  readonly approverCapability?: string;
}

export interface PolicyInput {
  readonly id: string;
  readonly rules: readonly PolicyRule[];
}

interface CommonAccessDecision {
  readonly version: 2;
  readonly authorityMode: AuthorityMode;
  readonly subjectId: string;
  readonly subjectType: PrincipalType;
  readonly action: string;
  readonly actionSensitivity: ActionSensitivity;
  readonly resourceId: string;
  readonly contextHash: string;
  readonly policyId: string;
  readonly policyVersion: string;
  readonly decidedAt: string;
}

interface CommonBoundAccessDecision extends CommonAccessDecision {
  readonly outcome: DecisionOutcome;
  readonly reasonCode: ReasonCode;
  readonly actingCredentialId: string;
  readonly effectiveScopeHash: string;
  readonly requiredApproverCapability?: string;
}

export type InactiveBoundDirectDenyReasonCode =
  | "CREDENTIAL_NOT_YET_VALID"
  | "CREDENTIAL_EXPIRED"
  | "CREDENTIAL_REVOKED";

export type TrustedBoundDirectReasonCode =
  | "POLICY_ALLOW"
  | "POLICY_DENY"
  | "HUMAN_APPROVAL_REQUIRED"
  | "CREDENTIAL_SUBJECT_MISMATCH"
  | "ACTION_OUTSIDE_CREDENTIAL_SCOPE"
  | "RESOURCE_OUTSIDE_CREDENTIAL_SCOPE"
  | "INSUFFICIENT_CAPABILITY"
  | "AFFILIATION_REQUIRED"
  | "ACTION_NOT_PERMITTED";

export type BoundDirectReasonCode =
  | InactiveBoundDirectDenyReasonCode
  | TrustedBoundDirectReasonCode;

interface CommonBoundDirectAccessDecision extends CommonBoundAccessDecision {
  readonly authorityMode: "DIRECT";
  /** @deprecated Direct-mode compatibility alias. When present it equals actingCredentialId. */
  readonly credentialId?: string;
  readonly grantorId?: never;
  readonly grantorType?: never;
  readonly grantorCredentialId?: never;
  readonly delegationId?: never;
  readonly delegationBindingHash?: never;
}

export interface InactiveBoundDirectDenyAccessDecision extends CommonBoundDirectAccessDecision {
  readonly outcome: "DENY";
  readonly reasonCode: InactiveBoundDirectDenyReasonCode;
  readonly requiredApproverCapability?: never;
  readonly unverifiedMetadata?: never;
}

export interface TrustedBoundDirectAccessDecision extends CommonBoundDirectAccessDecision {
  readonly reasonCode: TrustedBoundDirectReasonCode;
  readonly unverifiedMetadata?: UnverifiedMetadata;
}

export type BoundDirectAccessDecision =
  | InactiveBoundDirectDenyAccessDecision
  | TrustedBoundDirectAccessDecision;

export type UnboundDirectDenyReasonCode =
  | "CREDENTIAL_MISSING"
  | "CREDENTIAL_MALFORMED"
  | "CREDENTIAL_UNKNOWN";

export interface UnboundDirectDenyAccessDecision extends CommonAccessDecision {
  readonly authorityMode: "DIRECT";
  readonly outcome: "DENY";
  readonly reasonCode: UnboundDirectDenyReasonCode;
  readonly actingCredentialId?: never;
  readonly effectiveScopeHash?: never;
  readonly credentialId?: never;
  readonly grantorId?: never;
  readonly grantorType?: never;
  readonly grantorCredentialId?: never;
  readonly delegationId?: never;
  readonly delegationBindingHash?: never;
  readonly requiredApproverCapability?: never;
  readonly unverifiedMetadata?: never;
}

export type UnboundDelegatedDenyReasonCode =
  | "CREDENTIAL_MISSING"
  | "CREDENTIAL_MALFORMED"
  | "CREDENTIAL_UNKNOWN"
  | "DELEGATION_GRANTOR_CREDENTIAL_INVALID";

export interface UnboundDelegatedDenyAccessDecision extends CommonAccessDecision {
  readonly authorityMode: "DELEGATED";
  readonly outcome: "DENY";
  readonly reasonCode: UnboundDelegatedDenyReasonCode;
  readonly actingCredentialId?: never;
  readonly effectiveScopeHash?: never;
  readonly credentialId?: never;
  readonly grantorId?: never;
  readonly grantorType?: never;
  readonly grantorCredentialId?: never;
  readonly delegationId?: never;
  readonly delegationBindingHash?: never;
  readonly requiredApproverCapability?: never;
  readonly unverifiedMetadata?: never;
}

interface CommonActingOnlyDelegatedDenyAccessDecision extends CommonAccessDecision {
  readonly authorityMode: "DELEGATED";
  readonly outcome: "DENY";
  readonly actingCredentialId: string;
  readonly effectiveScopeHash: string;
  readonly credentialId?: never;
  readonly grantorId?: never;
  readonly grantorType?: never;
  readonly grantorCredentialId?: never;
  readonly delegationId?: never;
  readonly delegationBindingHash?: never;
  readonly requiredApproverCapability?: never;
}

export interface InactiveActingOnlyDelegatedDenyAccessDecision
  extends CommonActingOnlyDelegatedDenyAccessDecision {
  readonly reasonCode: "CREDENTIAL_NOT_YET_VALID" | "CREDENTIAL_EXPIRED" | "CREDENTIAL_REVOKED";
  readonly unverifiedMetadata?: never;
}

export interface TrustedActingOnlyDelegatedDenyAccessDecision
  extends CommonActingOnlyDelegatedDenyAccessDecision {
  readonly reasonCode:
    | "DELEGATION_MALFORMED"
    | "DELEGATION_UNKNOWN"
    | "DELEGATION_DELEGATE_MISMATCH"
    | "DELEGATION_IDENTITIES_NOT_DISTINCT";
  readonly unverifiedMetadata?: UnverifiedMetadata;
}

export type ActingOnlyDelegatedDenyAccessDecision =
  | InactiveActingOnlyDelegatedDenyAccessDecision
  | TrustedActingOnlyDelegatedDenyAccessDecision;

export type FullyBoundDelegatedReasonCode =
  | "POLICY_ALLOW"
  | "POLICY_DENY"
  | "HUMAN_APPROVAL_REQUIRED"
  | "DELEGATION_NOT_YET_VALID"
  | "DELEGATION_EXPIRED"
  | "DELEGATION_REVOKED"
  | "DELEGATION_POLICY_MISMATCH"
  | "DELEGATION_GRANTOR_CREDENTIAL_INVALID"
  | "DELEGATION_GRANTOR_MISMATCH"
  | "DELEGATION_DELEGATE_MISMATCH"
  | "DELEGATION_IDENTITIES_NOT_DISTINCT"
  | "ACTION_OUTSIDE_DELEGATION_SCOPE"
  | "RESOURCE_OUTSIDE_DELEGATION_SCOPE"
  | "INSUFFICIENT_DELEGATED_CAPABILITY"
  | "AFFILIATION_REQUIRED"
  | "ACTION_NOT_PERMITTED";

export interface DelegatedAccessDecision extends CommonBoundAccessDecision {
  readonly authorityMode: "DELEGATED";
  readonly reasonCode: FullyBoundDelegatedReasonCode;
  readonly credentialId?: never;
  readonly grantorId: string;
  readonly grantorType: PrincipalType;
  readonly grantorCredentialId: string;
  readonly delegationId: string;
  readonly delegationBindingHash: string;
  readonly unverifiedMetadata?: UnverifiedMetadata;
}

export type DirectAccessDecision = BoundDirectAccessDecision | UnboundDirectDenyAccessDecision;
export type BoundAccessDecision = BoundDirectAccessDecision | DelegatedAccessDecision;
export type AccessDecision =
  | DirectAccessDecision
  | DelegatedAccessDecision
  | UnboundDelegatedDenyAccessDecision
  | ActingOnlyDelegatedDenyAccessDecision;

interface CommonReceiptBinding {
  readonly authorityMode: AuthorityMode;
  readonly subjectId: string;
  readonly subjectType: PrincipalType;
  readonly actingCredentialId: string;
  readonly effectiveScopeHash: string;
  readonly action: string;
  readonly actionSensitivity: ActionSensitivity;
  readonly resourceId: string;
  readonly contextHash: string;
  readonly policyId: string;
  readonly policyVersion: string;
  readonly decision: DecisionOutcome;
  readonly reasonCode: ReasonCode;
  readonly requiredApproverCapability?: string;
}

interface CommonReceiptPayload extends CommonReceiptBinding {
  readonly version: 2;
  readonly nonce: string;
  readonly decidedAt: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
}

export interface DirectReceiptPayload extends CommonReceiptPayload {
  readonly authorityMode: "DIRECT";
  readonly credentialId: string;
  readonly grantorId?: never;
  readonly grantorType?: never;
  readonly grantorCredentialId?: never;
  readonly delegationId?: never;
  readonly delegationBindingHash?: never;
}

export interface DelegatedReceiptPayload extends CommonReceiptPayload {
  readonly authorityMode: "DELEGATED";
  readonly credentialId?: never;
  readonly grantorId: string;
  readonly grantorType: PrincipalType;
  readonly grantorCredentialId: string;
  readonly delegationId: string;
  readonly delegationBindingHash: string;
}

export type ReceiptPayload = DirectReceiptPayload | DelegatedReceiptPayload;

export interface SignedReceipt {
  readonly algorithm: "HMAC-SHA256";
  readonly payload: ReceiptPayload;
  readonly signature: string;
}

export interface DirectReceiptExpectedBinding extends CommonReceiptBinding {
  readonly authorityMode: "DIRECT";
  readonly credentialId: string;
  readonly grantorId?: never;
  readonly grantorType?: never;
  readonly grantorCredentialId?: never;
  readonly delegationId?: never;
  readonly delegationBindingHash?: never;
}

export interface DelegatedReceiptExpectedBinding extends CommonReceiptBinding {
  readonly authorityMode: "DELEGATED";
  readonly credentialId?: never;
  readonly grantorId: string;
  readonly grantorType: PrincipalType;
  readonly grantorCredentialId: string;
  readonly delegationId: string;
  readonly delegationBindingHash: string;
}

export type ReceiptExpectedBinding =
  | DirectReceiptExpectedBinding
  | DelegatedReceiptExpectedBinding;

interface CommonStepUpRequest {
  readonly version: 2;
  readonly id: string;
  readonly authorityMode: AuthorityMode;
  readonly subjectId: string;
  readonly subjectType: PrincipalType;
  readonly actingCredentialId: string;
  readonly effectiveScopeHash: string;
  readonly action: string;
  readonly actionSensitivity: ActionSensitivity;
  readonly resourceId: string;
  readonly contextHash: string;
  readonly policyId: string;
  readonly policyVersion: string;
  readonly requiredApproverCapability: string;
  readonly requestedAt: string;
  readonly expiresAt: string;
  readonly status: "PENDING" | "APPROVED" | "REJECTED" | "EXPIRED";
}

export interface DirectStepUpRequest extends CommonStepUpRequest {
  readonly authorityMode: "DIRECT";
  readonly credentialId?: string;
  readonly grantorId?: never;
  readonly grantorType?: never;
  readonly grantorCredentialId?: never;
  readonly delegationId?: never;
  readonly delegationBindingHash?: never;
}

export interface DelegatedStepUpRequest extends CommonStepUpRequest {
  readonly authorityMode: "DELEGATED";
  readonly credentialId?: never;
  readonly grantorId: string;
  readonly grantorType: PrincipalType;
  readonly grantorCredentialId: string;
  readonly delegationId: string;
  readonly delegationBindingHash: string;
}

export type StepUpRequest = DirectStepUpRequest | DelegatedStepUpRequest;

interface CommonStepUpAuthorization {
  readonly version: 2;
  readonly id: string;
  readonly requestId: string;
  readonly authorityMode: AuthorityMode;
  readonly subjectId: string;
  readonly subjectType: PrincipalType;
  readonly actingCredentialId: string;
  readonly effectiveScopeHash: string;
  readonly action: string;
  readonly actionSensitivity: ActionSensitivity;
  readonly resourceId: string;
  readonly contextHash: string;
  readonly policyId: string;
  readonly policyVersion: string;
  readonly requiredApproverCapability: string;
  readonly approvedBy: string;
  readonly approvedByType: PrincipalType;
  readonly approverCredentialId: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
}

export interface DirectStepUpAuthorization extends CommonStepUpAuthorization {
  readonly authorityMode: "DIRECT";
  readonly credentialId?: string;
  readonly grantorId?: never;
  readonly grantorType?: never;
  readonly grantorCredentialId?: never;
  readonly delegationId?: never;
  readonly delegationBindingHash?: never;
}

export interface DelegatedStepUpAuthorization extends CommonStepUpAuthorization {
  readonly authorityMode: "DELEGATED";
  readonly credentialId?: never;
  readonly grantorId: string;
  readonly grantorType: PrincipalType;
  readonly grantorCredentialId: string;
  readonly delegationId: string;
  readonly delegationBindingHash: string;
}

export type StepUpAuthorization =
  | DirectStepUpAuthorization
  | DelegatedStepUpAuthorization;

interface CommonStepUpAuthorizationBinding {
  readonly authorization: StepUpAuthorization;
  readonly requestId: string;
  readonly authorityMode: AuthorityMode;
  readonly subjectId: string;
  readonly subjectType: PrincipalType;
  readonly actingCredentialId: string;
  readonly effectiveScopeHash: string;
  readonly action: string;
  readonly actionSensitivity: ActionSensitivity;
  readonly resourceId: string;
  readonly contextHash: string;
  readonly policyId: string;
  readonly policyVersion: string;
  readonly requiredApproverCapability: string;
  readonly approvedBy: string;
  readonly approvedByType: PrincipalType;
  readonly approverCredentialId: string;
}

export interface DirectStepUpAuthorizationBinding extends CommonStepUpAuthorizationBinding {
  readonly authorityMode: "DIRECT";
  readonly credentialId: string;
  readonly grantorId?: never;
  readonly grantorType?: never;
  readonly grantorCredentialId?: never;
  readonly delegationId?: never;
  readonly delegationBindingHash?: never;
}

export interface DelegatedStepUpAuthorizationBinding extends CommonStepUpAuthorizationBinding {
  readonly authorityMode: "DELEGATED";
  readonly credentialId?: never;
  readonly grantorId: string;
  readonly grantorType: PrincipalType;
  readonly grantorCredentialId: string;
  readonly delegationId: string;
  readonly delegationBindingHash: string;
}

export type ConsumeStepUpAuthorizationRequest =
  | DirectStepUpAuthorizationBinding
  | DelegatedStepUpAuthorizationBinding;

export interface DecisionLogEntry {
  readonly id: string;
  readonly recordedAt: string;
  readonly principal: Principal;
  readonly decision: AccessDecision;
  readonly receipt?: {
    readonly algorithm: "HMAC-SHA256";
    readonly payload: ReceiptPayload;
    readonly signatureHash: string;
  };
}

export interface IssueCredentialRequest extends AuthorityScope {
  readonly principal: Principal;
  readonly expiresAt: string;
  readonly unverifiedMetadata?: UnverifiedMetadata;
}

export interface IssueDelegationRequest extends AuthorityScope {
  readonly grantor: Principal;
  readonly grantorCredential: Credential;
  readonly delegate: Principal;
  readonly policy: PolicyInput;
  readonly expiresAt: string;
}

interface CommonEvaluateRequest {
  readonly principal: Principal;
  readonly action: string;
  readonly resourceId: string;
  readonly actionContext: Readonly<Record<string, unknown>>;
  readonly policy: PolicyInput;
  readonly issueReceipt: boolean;
  readonly receiptExpiresAt?: string;
}

interface CommonDirectEvaluateRequest extends CommonEvaluateRequest {
  readonly authorityMode: "DIRECT";
  readonly delegateIdentityCredential?: never;
  readonly grantorCredential?: never;
  readonly delegation?: never;
}

export interface CredentialPresentDirectEvaluateRequest extends CommonDirectEvaluateRequest {
  readonly credential: Credential;
}

export interface CredentiallessDirectEvaluateRequest extends CommonDirectEvaluateRequest {
  readonly credential: null;
}

export type DirectEvaluateRequest =
  | CredentialPresentDirectEvaluateRequest
  | CredentiallessDirectEvaluateRequest;

export interface DelegatedEvaluateRequest extends CommonEvaluateRequest {
  readonly authorityMode: "DELEGATED";
  readonly credential?: never;
  readonly delegateIdentityCredential: Credential;
  readonly grantorCredential: Credential;
  readonly delegation: CapabilityDelegation;
}

export type EvaluateRequest = DirectEvaluateRequest | DelegatedEvaluateRequest;

export interface EvaluationResponse<TDecision extends AccessDecision = AccessDecision> {
  readonly logId: string;
  readonly decision: TDecision;
  readonly receipt?: SignedReceipt;
}

export interface StepUpRequestResponse {
  readonly decisionLogId: string;
  readonly request: StepUpRequest;
}

export interface ResolveStepUpRequest {
  readonly resolution: "APPROVE" | "REJECT";
  readonly approver: Principal;
  readonly approverCredential: Credential;
}

export type VerificationStatus = "ACTIVE" | "REVOKED" | "EXPIRED" | "INVALID";
export type EligibleActionStatus = "ELIGIBLE" | "APPROVAL_REQUIRED" | "INELIGIBLE";
export type RequiredApprovalStatus =
  | "NOT_REQUIRED"
  | "PENDING"
  | "APPROVED"
  | "REJECTED"
  | "EXPIRED";
export type ReceiptState = "NOT_ISSUED" | "UNCONSUMED" | "CONSUMED" | "REJECTED";

export interface DelegatedScopeView {
  readonly delegationId: string;
  readonly grantorId: string;
  readonly grantorType: PrincipalType;
  readonly capabilities: readonly string[];
  readonly allowedActions: readonly string[];
  readonly allowedResourceIds: readonly string[];
  readonly status: VerificationStatus;
}

export interface OnboardingView {
  readonly version: 1;
  readonly referenceOnly: true;
  readonly decisionLogId: string;
  readonly verificationStatus: VerificationStatus;
  readonly principal: Principal;
  readonly authorityMode: AuthorityMode;
  readonly delegatedScope: DelegatedScopeView | null;
  readonly eligibleActions: readonly {
    readonly action: string;
    readonly resourceId: string;
    readonly status: EligibleActionStatus;
    readonly reasonCode: string;
  }[];
  readonly requiredApproval: {
    readonly status: RequiredApprovalStatus;
    readonly requestId?: string;
  };
  readonly receipt: {
    readonly status: ReceiptState;
  };
  readonly policyId: string;
  readonly policyVersion: string;
}

export class ZkycApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string) {
    super(`zKYC reference API rejected the request (${code})`);
    this.name = "ZkycApiError";
    this.status = status;
    this.code = code;
  }
}

export class ZkycTransportError extends Error {
  readonly code: "NETWORK_ERROR" | "INVALID_RESPONSE";

  constructor(code: "NETWORK_ERROR" | "INVALID_RESPONSE") {
    super(`zKYC reference transport failed (${code})`);
    this.name = "ZkycTransportError";
    this.code = code;
  }
}

export interface ZkycReferenceClientOptions {
  readonly baseUrl: string;
  readonly fetch?: FetchLike;
}

function requireResponseCorrelation(condition: boolean): asserts condition {
  if (!condition) throw new InvalidProtocolResponse();
}

function compareAscii(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function sameCanonicalStrings(
  responseValues: readonly string[],
  requestValues: readonly string[],
): boolean {
  const normalized = [...requestValues].sort(compareAscii);
  return new Set(normalized).size === normalized.length &&
    responseValues.length === normalized.length &&
    responseValues.every((value, index) => value === normalized[index]);
}

function sameCanonicalAffiliations(
  responseValues: readonly Affiliation[],
  requestValues: readonly Affiliation[],
): boolean {
  const normalized = [...requestValues].sort((left, right) =>
    compareAscii(left.organizationId, right.organizationId) || compareAscii(left.role, right.role)
  );
  const keys = normalized.map(({ organizationId, role }) => `${organizationId}\u0000${role}`);
  return new Set(keys).size === keys.length &&
    responseValues.length === normalized.length &&
    responseValues.every((value, index) =>
      value.organizationId === normalized[index]?.organizationId &&
      value.role === normalized[index]?.role
    );
}

function sameUnverifiedMetadata(
  responseValue: UnverifiedMetadata | undefined,
  requestValue: UnverifiedMetadata | undefined,
): boolean {
  if (responseValue === undefined || requestValue === undefined) return responseValue === requestValue;
  if (responseValue.zkPassProofId !== requestValue.zkPassProofId) return false;
  const responseProofs = responseValue.contextualProofIds;
  const requestProofs = requestValue.contextualProofIds;
  if (responseProofs === undefined || requestProofs === undefined) return responseProofs === requestProofs;
  return sameCanonicalStrings(responseProofs, requestProofs);
}

function containsAll(values: readonly string[], required: readonly string[]): boolean {
  const available = new Set(values);
  return required.every((value) => available.has(value));
}

function containsAllAffiliations(
  values: readonly Affiliation[],
  required: readonly Affiliation[],
): boolean {
  const available = new Set(values.map(({ organizationId, role }) => `${organizationId}\u0000${role}`));
  return required.every(({ organizationId, role }) => available.has(`${organizationId}\u0000${role}`));
}

function delegationAttenuatesGrantor(
  delegation: CapabilityDelegation,
  grantorCredential: Credential,
): boolean {
  return Date.parse(delegation.issuedAt) >= Date.parse(grantorCredential.issuedAt) &&
    Date.parse(delegation.expiresAt) <= Date.parse(grantorCredential.expiresAt) &&
    !delegation.capabilities.includes("delegation:issue") &&
    containsAll(grantorCredential.capabilities, delegation.capabilities) &&
    containsAll(grantorCredential.allowedActions, delegation.allowedActions) &&
    containsAll(grantorCredential.allowedResourceIds, delegation.allowedResourceIds);
}

function activeAt(
  artifact: { readonly issuedAt: string; readonly expiresAt: string },
  at: string,
): boolean {
  const issuedAt = Date.parse(artifact.issuedAt);
  const expiresAt = Date.parse(artifact.expiresAt);
  const evaluatedAt = Date.parse(at);
  return Number.isFinite(issuedAt) && Number.isFinite(expiresAt) && Number.isFinite(evaluatedAt) &&
    issuedAt <= evaluatedAt && evaluatedAt < expiresAt;
}

function suppliedAuthoritySatisfiesRule(
  input: EvaluateRequest,
  rule: PolicyRule,
  decidedAt: string,
): boolean {
  if (input.authorityMode === "DIRECT") {
    const credential = input.credential;
    return credential !== null &&
      credential.principalId === input.principal.id &&
      credential.principalType === input.principal.type &&
      sameCanonicalAffiliations(credential.affiliations, input.principal.affiliations) &&
      activeAt(credential, decidedAt) &&
      credential.allowedActions.includes(input.action) &&
      credential.allowedResourceIds.includes(input.resourceId) &&
      containsAll(credential.capabilities, rule.requiredCapabilities) &&
      containsAllAffiliations(credential.affiliations, rule.requiredAffiliations);
  }
  return input.delegateIdentityCredential.principalId === input.principal.id &&
    input.delegateIdentityCredential.principalType === input.principal.type &&
    sameCanonicalAffiliations(
      input.delegateIdentityCredential.affiliations,
      input.principal.affiliations,
    ) &&
    input.delegateIdentityCredential.id !== input.grantorCredential.id &&
    activeAt(input.delegateIdentityCredential, decidedAt) &&
    activeAt(input.grantorCredential, decidedAt) &&
    activeAt(input.delegation, decidedAt) &&
    input.delegation.delegateId === input.principal.id &&
    input.delegation.delegateType === input.principal.type &&
    (input.delegation.delegateId !== input.delegation.grantorId ||
      input.delegation.delegateType !== input.delegation.grantorType) &&
    input.delegation.grantorCredentialId === input.grantorCredential.id &&
    input.delegation.grantorId === input.grantorCredential.principalId &&
    input.delegation.grantorType === input.grantorCredential.principalType &&
    activeAt(input.grantorCredential, input.delegation.issuedAt) &&
    Date.parse(input.delegation.expiresAt) <= Date.parse(input.grantorCredential.expiresAt) &&
    !input.delegation.capabilities.includes("delegation:issue") &&
    containsAll(input.grantorCredential.capabilities, input.delegation.capabilities) &&
    containsAll(input.grantorCredential.allowedActions, input.delegation.allowedActions) &&
    containsAll(input.grantorCredential.allowedResourceIds, input.delegation.allowedResourceIds) &&
    input.delegation.allowedActions.includes(input.action) &&
    input.delegation.allowedResourceIds.includes(input.resourceId) &&
    containsAll(input.delegation.capabilities, rule.requiredCapabilities) &&
    containsAllAffiliations(
      input.delegateIdentityCredential.affiliations,
      rule.requiredAffiliations,
    );
}

type DirectCredentialState =
  | { readonly status: "MISSING" }
  | { readonly status: "MALFORMED" }
  | { readonly status: "VALID"; readonly credential: Credential };

type DelegatedCredentialState =
  | { readonly status: "MALFORMED" }
  | { readonly status: "VALID"; readonly credential: Credential };

type GrantorCredentialState =
  | { readonly status: "MALFORMED" }
  | { readonly status: "VALID"; readonly credential: Credential };

type DelegationState =
  | { readonly status: "MALFORMED" }
  | { readonly status: "VALID"; readonly delegation: CapabilityDelegation };

function credentialTimeState(
  artifact: { readonly issuedAt: string; readonly expiresAt: string },
  decidedAtValue: string,
): "NOT_YET_VALID" | "EXPIRED" | "ACTIVE" {
  const decidedAt = Date.parse(decidedAtValue);
  if (decidedAt < Date.parse(artifact.issuedAt)) return "NOT_YET_VALID";
  if (decidedAt >= Date.parse(artifact.expiresAt)) return "EXPIRED";
  return "ACTIVE";
}

function delegatedDenialMatchesRequest(
  decision: AccessDecision,
  input: DelegatedEvaluateRequest,
  credentialState: DelegatedCredentialState,
  delegationState: DelegationState,
  grantorCredentialId: string | undefined,
): boolean {
  if (decision.reasonCode === "DELEGATION_GRANTOR_CREDENTIAL_INVALID" &&
      decision.actingCredentialId === undefined) {
    return true;
  }
  if (credentialState.status === "MALFORMED") {
    return decision.reasonCode === "CREDENTIAL_MALFORMED" &&
      decision.actingCredentialId === undefined;
  }

  const credential = credentialState.credential;
  if (decision.actingCredentialId === undefined) {
    return decision.reasonCode === "CREDENTIAL_UNKNOWN";
  }
  if (
    decision.actingCredentialId !== credential.id ||
    decision.effectiveScopeHash !== credential.scopeHash
  ) return false;

  const timeState = credentialTimeState(credential, decision.decidedAt);
  if (decision.reasonCode === "CREDENTIAL_NOT_YET_VALID") return timeState === "NOT_YET_VALID";
  if (decision.reasonCode === "CREDENTIAL_EXPIRED") return timeState === "EXPIRED";
  if (decision.reasonCode === "CREDENTIAL_REVOKED") return timeState === "ACTIVE";
  if (timeState !== "ACTIVE") return false;

  const identitiesAreDistinct = credential.id !== grantorCredentialId;
  if (decision.reasonCode === "DELEGATION_IDENTITIES_NOT_DISTINCT") {
    return !identitiesAreDistinct;
  }
  if (!identitiesAreDistinct) return false;

  const delegateMatches = credential.principalId === input.principal.id &&
    credential.principalType === input.principal.type &&
    sameCanonicalAffiliations(credential.affiliations, input.principal.affiliations);
  if (decision.reasonCode === "DELEGATION_DELEGATE_MISMATCH") return !delegateMatches;
  if (!delegateMatches) return false;

  if (decision.reasonCode === "DELEGATION_MALFORMED") {
    return delegationState.status === "MALFORMED";
  }
  if (decision.reasonCode === "DELEGATION_UNKNOWN") {
    return delegationState.status === "VALID";
  }
  return true;
}

function fullyBoundDelegatedDenialMatchesRequest(
  decision: AccessDecision,
  input: DelegatedEvaluateRequest,
  credentialState: DelegatedCredentialState,
  grantorCredentialState: GrantorCredentialState,
  delegationState: DelegationState,
  grantorCredentialId: string | undefined,
  expectedPolicy: CanonicalPolicy,
): boolean {
  if (
    credentialState.status !== "VALID" ||
    delegationState.status !== "VALID" ||
    decision.grantorId === undefined
  ) return false;

  const credential = credentialState.credential;
  const delegation = delegationState.delegation;
  if (
    credentialTimeState(credential, decision.decidedAt) !== "ACTIVE" ||
    credential.principalId !== input.principal.id ||
    credential.principalType !== input.principal.type ||
    !sameCanonicalAffiliations(credential.affiliations, input.principal.affiliations) ||
    credential.id === grantorCredentialId ||
    credential.issuerId !== delegation.issuerId ||
    decision.actingCredentialId !== credential.id ||
    decision.effectiveScopeHash !== delegation.scopeHash ||
    decision.grantorId !== delegation.grantorId ||
    decision.grantorType !== delegation.grantorType ||
    decision.grantorCredentialId !== delegation.grantorCredentialId ||
    decision.delegationId !== delegation.id ||
    decision.delegationBindingHash !== delegation.delegationBindingHash ||
    !sameUnverifiedMetadata(decision.unverifiedMetadata, credential.unverifiedMetadata)
  ) return false;

  const policyMatches = delegation.policyId === expectedPolicy.id &&
    delegation.policyVersion === expectedPolicy.version;
  if (decision.reasonCode === "DELEGATION_POLICY_MISMATCH") return !policyMatches;
  if (!policyMatches) return false;

  const timeState = credentialTimeState(delegation, decision.decidedAt);
  if (decision.reasonCode === "DELEGATION_NOT_YET_VALID") return timeState === "NOT_YET_VALID";
  if (decision.reasonCode === "DELEGATION_EXPIRED") return timeState === "EXPIRED";
  if (timeState !== "ACTIVE") return false;

  if (decision.reasonCode === "DELEGATION_REVOKED") return true;
  if (decision.reasonCode === "DELEGATION_GRANTOR_CREDENTIAL_INVALID") return true;
  if (decision.reasonCode === "DELEGATION_IDENTITIES_NOT_DISTINCT") return false;
  const delegateMismatch = delegation.delegateId !== input.principal.id ||
    delegation.delegateType !== input.principal.type ||
    delegation.delegateId !== credential.principalId ||
    delegation.delegateType !== credential.principalType;
  if (decision.reasonCode === "DELEGATION_DELEGATE_MISMATCH") return delegateMismatch;
  if (delegateMismatch) return false;

  if (grantorCredentialState.status !== "VALID") return false;
  const grantorCredential = grantorCredentialState.credential;
  if (
    credentialTimeState(grantorCredential, decision.decidedAt) !== "ACTIVE" ||
    grantorCredential.issuerId !== delegation.issuerId
  ) return false;

  const grantorTupleMatches = grantorCredential.id === delegation.grantorCredentialId &&
    grantorCredential.principalId === delegation.grantorId &&
    grantorCredential.principalType === delegation.grantorType;
  if (decision.reasonCode === "DELEGATION_GRANTOR_MISMATCH") return !grantorTupleMatches;
  if (!grantorTupleMatches || !delegationAttenuatesGrantor(delegation, grantorCredential)) return false;

  const actionInScope = grantorCredential.allowedActions.includes(input.action) &&
    delegation.allowedActions.includes(input.action);
  if (decision.reasonCode === "ACTION_OUTSIDE_DELEGATION_SCOPE") return !actionInScope;
  if (!actionInScope) return false;

  const resourceInScope = grantorCredential.allowedResourceIds.includes(input.resourceId) &&
    delegation.allowedResourceIds.includes(input.resourceId);
  if (decision.reasonCode === "RESOURCE_OUTSIDE_DELEGATION_SCOPE") return !resourceInScope;
  if (!resourceInScope) return false;

  if (decision.requiredApproverCapability !== undefined) return false;
  const rule = expectedPolicy.rules.find((candidate) => candidate.action === decision.action);
  if (rule === undefined) return decision.reasonCode === "ACTION_NOT_PERMITTED";
  if (rule.actionSensitivity !== decision.actionSensitivity) return false;
  if (rule.effect === "DENY") return decision.reasonCode === "POLICY_DENY";
  if (decision.reasonCode === "POLICY_DENY") return false;

  const delegatedCapabilitiesSatisfyRule = containsAll(
    delegation.capabilities,
    rule.requiredCapabilities,
  );
  if (decision.reasonCode === "INSUFFICIENT_DELEGATED_CAPABILITY") {
    return !delegatedCapabilitiesSatisfyRule;
  }
  if (!delegatedCapabilitiesSatisfyRule) return false;

  const actingAffiliationsSatisfyRule = containsAllAffiliations(
    credential.affiliations,
    rule.requiredAffiliations,
  );
  if (decision.reasonCode === "AFFILIATION_REQUIRED") {
    return !actingAffiliationsSatisfyRule;
  }
  return false;
}

function directDenialMatchesRequest(
  decision: AccessDecision,
  rule: PolicyRule | undefined,
  input: CredentialPresentDirectEvaluateRequest | CredentiallessDirectEvaluateRequest,
  credentialState: DirectCredentialState,
): boolean {
  if (credentialState.status === "MISSING") {
    return decision.reasonCode === "CREDENTIAL_MISSING";
  }
  if (credentialState.status === "MALFORMED") {
    return decision.reasonCode === "CREDENTIAL_MALFORMED";
  }
  const credential = credentialState.credential;
  if (
    decision.reasonCode === "CREDENTIAL_MISSING" ||
    decision.reasonCode === "CREDENTIAL_MALFORMED"
  ) return false;
  if (decision.reasonCode === "CREDENTIAL_UNKNOWN") return true;

  const decidedAt = Date.parse(decision.decidedAt);
  const issuedAt = Date.parse(credential.issuedAt);
  const expiresAt = Date.parse(credential.expiresAt);
  const notYetValid = decidedAt < issuedAt;
  const expired = decidedAt >= expiresAt;
  const active = !notYetValid && !expired;
  if (decision.reasonCode === "CREDENTIAL_NOT_YET_VALID") return notYetValid;
  if (decision.reasonCode === "CREDENTIAL_EXPIRED") return expired;
  if (decision.reasonCode === "CREDENTIAL_REVOKED") return active;
  if (!active) return false;

  const subjectMatches = credential.principalId === input.principal.id &&
    credential.principalType === input.principal.type &&
    sameCanonicalAffiliations(credential.affiliations, input.principal.affiliations);
  if (decision.reasonCode === "CREDENTIAL_SUBJECT_MISMATCH") return !subjectMatches;
  if (!subjectMatches) return false;

  const actionInScope = credential.allowedActions.includes(input.action);
  if (decision.reasonCode === "ACTION_OUTSIDE_CREDENTIAL_SCOPE") return !actionInScope;
  if (!actionInScope) return false;

  const resourceInScope = credential.allowedResourceIds.includes(input.resourceId);
  if (decision.reasonCode === "RESOURCE_OUTSIDE_CREDENTIAL_SCOPE") return !resourceInScope;
  if (!resourceInScope) return false;

  if (decision.reasonCode === "ACTION_NOT_PERMITTED") return rule === undefined;
  if (rule === undefined) return false;
  if (decision.reasonCode === "POLICY_DENY") return rule.effect === "DENY";
  if (rule.effect === "DENY") return false;

  const capabilitiesSatisfyRule = containsAll(credential.capabilities, rule.requiredCapabilities);
  if (decision.reasonCode === "INSUFFICIENT_CAPABILITY") return !capabilitiesSatisfyRule;
  if (!capabilitiesSatisfyRule) return false;

  if (decision.reasonCode === "AFFILIATION_REQUIRED") {
    return !containsAllAffiliations(credential.affiliations, rule.requiredAffiliations);
  }
  return false;
}

function decisionMatchesRequestedPolicy(
  decision: AccessDecision,
  policy: CanonicalPolicy,
  input: EvaluateRequest,
  directCredentialState: DirectCredentialState | undefined,
  delegatedCredentialState: DelegatedCredentialState | undefined,
  grantorCredentialState: GrantorCredentialState | undefined,
  delegationState: DelegationState | undefined,
  grantorCredentialId: string | undefined,
): boolean {
  const rule = policy.rules.find((candidate) => candidate.action === decision.action);
  if (decision.actionSensitivity !== (rule?.actionSensitivity ?? "ROUTINE")) return false;
  if (decision.outcome === "ALLOW") {
    return decision.reasonCode === "POLICY_ALLOW" &&
      rule?.effect === "ALLOW" &&
      (input.authorityMode === "DIRECT" ||
        (delegatedCredentialState?.status === "VALID" &&
          grantorCredentialState?.status === "VALID" &&
          delegationState?.status === "VALID" &&
          grantorCredentialState.credential.issuerId === delegationState.delegation.issuerId)) &&
      suppliedAuthoritySatisfiesRule(input, rule, decision.decidedAt) &&
      decision.requiredApproverCapability === undefined;
  }
  if (decision.outcome === "STEP_UP") {
    return decision.reasonCode === "HUMAN_APPROVAL_REQUIRED" &&
      rule?.effect === "STEP_UP" &&
      (input.authorityMode === "DIRECT" ||
        (delegatedCredentialState?.status === "VALID" &&
          grantorCredentialState?.status === "VALID" &&
          delegationState?.status === "VALID" &&
          grantorCredentialState.credential.issuerId === delegationState.delegation.issuerId)) &&
      suppliedAuthoritySatisfiesRule(input, rule, decision.decidedAt) &&
      decision.requiredApproverCapability === rule.approverCapability;
  }
  if (input.authorityMode === "DIRECT") {
    return directCredentialState !== undefined &&
      decision.requiredApproverCapability === undefined &&
      directDenialMatchesRequest(decision, rule, input, directCredentialState);
  }
  if (decision.grantorId !== undefined) {
    return delegatedCredentialState !== undefined &&
      grantorCredentialState !== undefined &&
      delegationState !== undefined &&
      fullyBoundDelegatedDenialMatchesRequest(
        decision,
        input,
        delegatedCredentialState,
        grantorCredentialState,
        delegationState,
        grantorCredentialId,
        policy,
      );
  }
  return delegatedCredentialState !== undefined &&
    delegationState !== undefined &&
    decision.requiredApproverCapability === undefined &&
    delegatedDenialMatchesRequest(
      decision,
      input,
      delegatedCredentialState,
      delegationState,
      grantorCredentialId,
    );
}

export class ZkycReferenceClient {
  readonly #baseUrl: URL;
  readonly #fetch: FetchLike;

  constructor(options: ZkycReferenceClientOptions) {
    const normalized = options.baseUrl.endsWith("/") ? options.baseUrl : `${options.baseUrl}/`;
    const runtimeLocation = Reflect.get(globalThis, "location") as { readonly href: string } | undefined;
    this.#baseUrl = new URL(normalized, runtimeLocation?.href);
    const fetchImplementation = options.fetch ?? globalThis.fetch;
    if (typeof fetchImplementation !== "function") {
      throw new ZkycTransportError("NETWORK_ERROR");
    }
    this.#fetch = fetchImplementation.bind(globalThis);
  }

  async #request<T>(
    path: string,
    validate: (value: unknown) => T | Promise<T>,
    method = "GET",
    body?: unknown,
  ): Promise<T> {
    let response: Response;
    try {
      response = await this.#fetch(new URL(path, this.#baseUrl), {
        method,
        ...(body === undefined
          ? {}
          : { headers: { "content-type": "application/json" }, body: JSON.stringify(body) }),
      });
    } catch {
      throw new ZkycTransportError("NETWORK_ERROR");
    }

    const contentType = response.headers.get("content-type") ?? "";
    const mediaType = contentType.split(";", 1)[0]?.trim().toLowerCase() ?? "";
    if (mediaType !== "application/json" && !/^application\/[a-z0-9!#$&^_.+-]+\+json$/.test(mediaType)) {
      throw new ZkycTransportError("INVALID_RESPONSE");
    }
    let parsed: unknown;
    try {
      parsed = await response.json();
    } catch {
      throw new ZkycTransportError("INVALID_RESPONSE");
    }
    if (!response.ok) {
      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
        throw new ZkycTransportError("INVALID_RESPONSE");
      }
      const envelope = parsed as Record<string, unknown>;
      if (
        Object.keys(envelope).length !== 1 ||
        !Object.hasOwn(envelope, "error") ||
        typeof envelope.error !== "object" ||
        envelope.error === null ||
        Array.isArray(envelope.error)
      ) {
        throw new ZkycTransportError("INVALID_RESPONSE");
      }
      const error = envelope.error as Record<string, unknown>;
      if (
        Object.keys(error).some((key) => key !== "code" && key !== "message") ||
        !Object.hasOwn(error, "code") ||
        !Object.hasOwn(error, "message") ||
        typeof error.code !== "string" ||
        !/^[A-Z][A-Z0-9_]*$/.test(error.code) ||
        typeof error.message !== "string"
      ) {
        throw new ZkycTransportError("INVALID_RESPONSE");
      }
      throw new ZkycApiError(response.status, error.code);
    }
    try {
      return await validate(parsed);
    } catch (error) {
      if (error instanceof InvalidProtocolResponse) {
        throw new ZkycTransportError("INVALID_RESPONSE");
      }
      throw error;
    }
  }

  health() {
    return this.#request("health", validateHealthResponse);
  }

  issueCredential(input: IssueCredentialRequest) {
    return this.#request("credentials", async (value) => {
      const response = validateCredentialResponse(value);
      const expectedScopeHash = await computeScopeHash(input);
      requireResponseCorrelation(
        response.credential.principalId === input.principal.id &&
        response.credential.principalType === input.principal.type &&
        sameCanonicalAffiliations(response.credential.affiliations, input.principal.affiliations) &&
        sameCanonicalStrings(response.credential.capabilities, input.capabilities) &&
        sameCanonicalStrings(response.credential.allowedActions, input.allowedActions) &&
        sameCanonicalStrings(response.credential.allowedResourceIds, input.allowedResourceIds) &&
        response.credential.scopeHash === expectedScopeHash &&
        response.credential.expiresAt === input.expiresAt &&
        sameUnverifiedMetadata(response.credential.unverifiedMetadata, input.unverifiedMetadata),
      );
      return response;
    }, "POST", input);
  }

  revokeCredential(credentialId: string, input: { readonly reason: string }) {
    return this.#request(
      `credentials/${encodeURIComponent(credentialId)}/revoke`,
      validateRevocationResponse,
      "POST",
      input,
    );
  }

  issueDelegation(input: IssueDelegationRequest) {
    return this.#request("delegations", async (value) => {
      const response = validateDelegationResponse(value);
      const delegation = response.delegation;
      const expectedPolicy = await canonicalPolicy(input.policy);
      const expectedScopeHash = await computeScopeHash(input);
      const expectedGrantorCredentialScopeHash = await computeScopeHash(input.grantorCredential);
      const expectedBindingHash = await computeDelegationBindingHash(delegation);
      requireResponseCorrelation(
        input.grantorCredential.principalId === input.grantor.id &&
        input.grantorCredential.principalType === input.grantor.type &&
        sameCanonicalAffiliations(input.grantorCredential.affiliations, input.grantor.affiliations) &&
        input.grantorCredential.scopeHash === expectedGrantorCredentialScopeHash &&
        delegation.grantorCredentialId === input.grantorCredential.id &&
        delegation.issuerId === input.grantorCredential.issuerId &&
        delegation.grantorId === input.grantor.id &&
        delegation.grantorType === input.grantor.type &&
        (input.grantor.id !== input.delegate.id || input.grantor.type !== input.delegate.type) &&
        delegation.delegateId === input.delegate.id &&
        delegation.delegateType === input.delegate.type &&
        delegation.policyId === input.policy.id &&
        delegation.policyVersion === expectedPolicy.version &&
        sameCanonicalStrings(delegation.capabilities, input.capabilities) &&
        sameCanonicalStrings(delegation.allowedActions, input.allowedActions) &&
        sameCanonicalStrings(delegation.allowedResourceIds, input.allowedResourceIds) &&
        delegation.scopeHash === expectedScopeHash &&
        delegation.delegationBindingHash === expectedBindingHash &&
        activeAt(input.grantorCredential, delegation.issuedAt) &&
        Date.parse(delegation.expiresAt) <= Date.parse(input.grantorCredential.expiresAt) &&
        !delegation.capabilities.includes("delegation:issue") &&
        containsAll(input.grantorCredential.capabilities, delegation.capabilities) &&
        containsAll(input.grantorCredential.allowedActions, delegation.allowedActions) &&
        containsAll(input.grantorCredential.allowedResourceIds, delegation.allowedResourceIds) &&
        delegation.expiresAt === input.expiresAt,
      );
      return response;
    }, "POST", input);
  }

  revokeDelegation(delegationId: string, input: { readonly reason: string }) {
    return this.#request(
      `delegations/${encodeURIComponent(delegationId)}/revoke`,
      validateRevocationResponse,
      "POST",
      input,
    );
  }

  evaluate(input: EvaluateRequest): Promise<EvaluationResponse> {
    return this.#request("evaluations", async (value) => {
      const response = validateEvaluationResponse(value);
      const decision = response.decision;
      const expectedPolicy = await canonicalPolicy(input.policy);
      const expectedContextHash = await computeContextHash(input.actionContext);
      let directCredentialState: DirectCredentialState | undefined;
      let delegatedCredentialState: DelegatedCredentialState | undefined;
      let grantorCredentialState: GrantorCredentialState | undefined;
      let delegationState: DelegationState | undefined;
      let grantorCredentialId: string | undefined;
      let correlationInput = input;
      if (input.authorityMode === "DIRECT") {
        if (input.credential === null) {
          directCredentialState = { status: "MISSING" };
        } else {
          try {
            const credential = validateCredentialResponse({ credential: input.credential }).credential;
            directCredentialState = credential.scopeHash === await computeScopeHash(credential)
              ? { status: "VALID", credential }
              : { status: "MALFORMED" };
          } catch {
            directCredentialState = { status: "MALFORMED" };
          }
        }
      } else {
        try {
          const suppliedGrantorCredential = input.grantorCredential as unknown;
          if (
            typeof suppliedGrantorCredential === "object" &&
            suppliedGrantorCredential !== null &&
            !Array.isArray(suppliedGrantorCredential)
          ) {
            const id = Reflect.get(suppliedGrantorCredential, "id") as unknown;
            grantorCredentialId = typeof id === "string" ? id : undefined;
          }
        } catch {
          grantorCredentialId = undefined;
        }
        try {
          const credential = validateCredentialResponse({
            credential: input.grantorCredential,
          }).credential;
          grantorCredentialState = credential.scopeHash === await computeScopeHash(credential)
            ? { status: "VALID", credential }
            : { status: "MALFORMED" };
        } catch {
          grantorCredentialState = { status: "MALFORMED" };
        }
        try {
          const credential = validateCredentialResponse({
            credential: input.delegateIdentityCredential,
          }).credential;
          delegatedCredentialState = credential.scopeHash === await computeScopeHash(credential)
            ? { status: "VALID", credential }
            : { status: "MALFORMED" };
        } catch {
          delegatedCredentialState = { status: "MALFORMED" };
        }
        try {
          const delegation = validateDelegationResponse({ delegation: input.delegation }).delegation;
          const structurallyDistinct = delegation.grantorId !== delegation.delegateId ||
            delegation.grantorType !== delegation.delegateType;
          delegationState = structurallyDistinct &&
              delegation.scopeHash === await computeScopeHash(delegation) &&
              delegation.delegationBindingHash === await computeDelegationBindingHash(delegation)
            ? { status: "VALID", delegation }
            : { status: "MALFORMED" };
        } catch {
          delegationState = { status: "MALFORMED" };
        }
        if (delegatedCredentialState.status === "VALID" && delegationState.status === "VALID") {
          correlationInput = {
            ...input,
            delegateIdentityCredential: delegatedCredentialState.credential,
            delegation: delegationState.delegation,
            ...(grantorCredentialState.status === "VALID"
              ? { grantorCredential: grantorCredentialState.credential }
              : {}),
          };
        }
      }
      requireResponseCorrelation(
        decision.authorityMode === input.authorityMode &&
        decision.subjectId === input.principal.id &&
        decision.subjectType === input.principal.type &&
        decision.action === input.action &&
        decision.resourceId === input.resourceId &&
        decision.contextHash === expectedContextHash &&
        decision.policyId === input.policy.id &&
        decision.policyVersion === expectedPolicy.version &&
        decisionMatchesRequestedPolicy(
          decision,
          expectedPolicy,
          correlationInput,
          directCredentialState,
          delegatedCredentialState,
          grantorCredentialState,
          delegationState,
          grantorCredentialId,
        ) &&
        (response.receipt === undefined
          ? !(input.issueReceipt && decision.outcome === "ALLOW")
          : input.issueReceipt &&
            decision.outcome === "ALLOW" &&
            input.receiptExpiresAt !== undefined &&
            Date.parse(response.receipt.payload.expiresAt) <= Date.parse(input.receiptExpiresAt)),
      );
      if (input.authorityMode === "DIRECT") {
        const isUnbound = decision.actingCredentialId === undefined &&
          decision.effectiveScopeHash === undefined &&
          decision.credentialId === undefined;
        if (isUnbound) {
          requireResponseCorrelation(
            directCredentialState !== undefined &&
            decision.authorityMode === "DIRECT" &&
            decision.outcome === "DENY" &&
            (directCredentialState.status === "MISSING"
              ? decision.reasonCode === "CREDENTIAL_MISSING"
              : directCredentialState.status === "MALFORMED"
              ? decision.reasonCode === "CREDENTIAL_MALFORMED"
              : decision.reasonCode === "CREDENTIAL_UNKNOWN") &&
            response.receipt === undefined,
          );
        } else {
          requireResponseCorrelation(directCredentialState?.status === "VALID");
          const credential = directCredentialState.credential;
          requireResponseCorrelation(
            decision.authorityMode === "DIRECT" &&
            decision.actingCredentialId === credential.id &&
            decision.effectiveScopeHash === credential.scopeHash,
          );
        }
      } else {
        const isUnbound = decision.actingCredentialId === undefined &&
          decision.effectiveScopeHash === undefined;
        if (isUnbound) {
          requireResponseCorrelation(
            decision.authorityMode === "DELEGATED" &&
            decision.outcome === "DENY" &&
            (decision.reasonCode === "CREDENTIAL_MISSING" ||
              decision.reasonCode === "CREDENTIAL_MALFORMED" ||
              decision.reasonCode === "CREDENTIAL_UNKNOWN" ||
              decision.reasonCode === "DELEGATION_GRANTOR_CREDENTIAL_INVALID") &&
            response.receipt === undefined,
          );
        } else {
          requireResponseCorrelation(delegatedCredentialState?.status === "VALID");
          const delegateCredential = delegatedCredentialState.credential;
          requireResponseCorrelation(
            decision.authorityMode === "DELEGATED" &&
            decision.actingCredentialId === delegateCredential.id,
          );
          if (decision.grantorId === undefined) {
            const delegateIdentityMismatch =
              delegateCredential.principalId !== input.principal.id ||
              delegateCredential.principalType !== input.principal.type ||
              !sameCanonicalAffiliations(
                delegateCredential.affiliations,
                input.principal.affiliations,
              );
            requireResponseCorrelation(
              decision.outcome === "DENY" &&
              decision.effectiveScopeHash === delegateCredential.scopeHash &&
              response.receipt === undefined &&
              (decision.reasonCode !== "DELEGATION_IDENTITIES_NOT_DISTINCT" ||
                delegateCredential.id === grantorCredentialId) &&
              (decision.reasonCode !== "DELEGATION_DELEGATE_MISMATCH" ||
                delegateIdentityMismatch),
            );
          } else {
            requireResponseCorrelation(delegationState?.status === "VALID");
            const delegation = delegationState.delegation;
            requireResponseCorrelation(
              delegateCredential.issuerId === delegation.issuerId &&
              decision.effectiveScopeHash === delegation.scopeHash &&
              decision.grantorId === delegation.grantorId &&
              decision.grantorType === delegation.grantorType &&
              decision.grantorCredentialId === delegation.grantorCredentialId &&
              decision.delegationId === delegation.id &&
              decision.delegationBindingHash === delegation.delegationBindingHash,
            );
          }
        }
      }
      return response;
    }, "POST", input);
  }

  createStepUpRequest(input: { readonly decisionLogId: string; readonly expiresAt: string }) {
    return this.#request("step-up/requests", (value) => {
      const response = validateStepUpRequestResponse(value);
      requireResponseCorrelation(
        response.decisionLogId === input.decisionLogId &&
        response.request.expiresAt === input.expiresAt &&
        response.request.status === "PENDING",
      );
      return response;
    }, "POST", input);
  }

  resolveStepUpRequest(requestId: string, input: ResolveStepUpRequest) {
    return this.#request(
      `step-up/requests/${encodeURIComponent(requestId)}/resolve`,
      (value) => {
        const response = validateResolutionResponse(value);
        if (response.ok) {
          requireResponseCorrelation(
            input.resolution === "APPROVE" &&
            response.authorization.requestId === requestId &&
            response.authorization.approvedBy === input.approver.id &&
            response.authorization.approvedByType === input.approver.type &&
            response.authorization.approverCredentialId === input.approverCredential.id,
          );
        } else if (input.resolution === "REJECT") {
          requireResponseCorrelation(response.reasonCode === "STEP_UP_REJECTED");
        }
        return response;
      },
      "POST",
      input,
    );
  }

  consumeStepUpAuthorization(input: ConsumeStepUpAuthorizationRequest) {
    return this.#request("step-up/authorizations/consume", validateAuthorizationConsumeResponse, "POST", input);
  }

  consumeReceipt(input: { readonly receipt: SignedReceipt; readonly expected: ReceiptExpectedBinding }) {
    return this.#request("receipts/consume", validateReceiptConsumeResponse, "POST", input);
  }

  getOnboardingView(decisionLogId: string) {
    return this.#request(
      `zkya/onboarding-views/${encodeURIComponent(decisionLogId)}`,
      (value) => {
        const response = validateOnboardingView(value);
        requireResponseCorrelation(response.decisionLogId === decisionLogId);
        return response;
      },
    );
  }

  getDecisionLog() {
    return this.#request("decision-log", validateDecisionLogResponse);
  }
}
