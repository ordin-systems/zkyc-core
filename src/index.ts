export {
  DECISION_OUTCOMES,
  REASON_CODES,
  ActionSensitivity,
  DomainValidationError,
  createPrincipal,
  validateAction,
  validateCapability,
  type Affiliation,
  type DecisionOutcome,
  type Principal,
  type ReasonCode,
  type UnverifiedMetadata,
} from "./domain.js";
export { canonicalJson, sha256Version } from "./canonical.js";
export {
  CredentialAuthority,
  type Credential,
  type CredentialStatus,
  type CredentialStatusCode,
  type IssueCredentialInput,
} from "./credentials.js";
export {
  createPolicy,
  type CreatePolicyInput,
  type PermissionRule,
  type Policy,
} from "./policy.js";
export {
  evaluateAccess,
  type AccessDecision,
  type AccessEvaluationInput,
} from "./evaluation.js";
export {
  InMemoryAtomicNonceStore,
  type AtomicNonceStore,
} from "./nonce.js";
export {
  HumanStepUpService,
  type StepUpAuthorization,
  type StepUpFailureCode,
  type StepUpRequest,
  type StepUpResolutionResult,
  type StepUpStatus,
} from "./step-up.js";
export {
  signReceipt,
  verifyAndConsumeReceipt,
  verifyReceipt,
  type ReceiptExpectedBinding,
  type ReceiptInspectionBinding,
  type ReceiptPayload,
  type ReceiptVerification,
  type ReceiptVerificationCode,
  type SignedReceipt,
} from "./receipts.js";
