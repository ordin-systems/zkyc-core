import { useCallback, useMemo, useState } from "react";
import {
  ZkycApiError,
  ZkycReferenceClient,
  ZkycTransportError,
  type AccessDecision,
  type DecisionLogEntry,
  type SignedReceipt,
  type StepUpAuthorization,
  type StepUpRequest,
} from "@ordin/zkyc-sdk-reference";
import { scenarios } from "./scenarios.js";

const defaultClient = new ZkycReferenceClient({
  baseUrl: import.meta.env.VITE_ZKYC_API_URL ?? "/api/",
});

export type CockpitClient = Pick<
  ZkycReferenceClient,
  | "issueCredential"
  | "evaluate"
  | "createStepUpRequest"
  | "resolveStepUpRequest"
  | "consumeStepUpAuthorization"
  | "consumeReceipt"
  | "getDecisionLog"
>;

export interface AppProps {
  readonly client?: CockpitClient;
}

function future(minutes: number): string {
  return new Date(Date.now() + minutes * 60_000).toISOString();
}

function errorMessage(error: unknown): string {
  if (error instanceof ZkycApiError) return `API rejected the request: ${error.code}`;
  if (error instanceof ZkycTransportError) return `Transport unavailable: ${error.code}`;
  return "The reference flow failed closed.";
}

export function App({ client = defaultClient }: AppProps = {}) {
  const [scenarioId, setScenarioId] = useState(scenarios[0]?.id ?? "");
  const [decision, setDecision] = useState<AccessDecision | null>(null);
  const [receipt, setReceipt] = useState<SignedReceipt | null>(null);
  const [stepUpRequest, setStepUpRequest] = useState<StepUpRequest | null>(null);
  const [authorization, setAuthorization] = useState<StepUpAuthorization | null>(null);
  const [resolutionReason, setResolutionReason] = useState<string | null>(null);
  const [consumption, setConsumption] = useState<string | null>(null);
  const [entries, setEntries] = useState<readonly DecisionLogEntry[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const scenario = useMemo(
    () => scenarios.find((candidate) => candidate.id === scenarioId) ?? scenarios[0],
    [scenarioId],
  );

  const refreshLog = useCallback(async () => {
    const log = await client.getDecisionLog();
    setEntries(log.entries);
  }, [client]);

  const refreshLogSafely = useCallback(async () => {
    setBusy("refresh");
    setError(null);
    try {
      await refreshLog();
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setBusy(null);
    }
  }, [refreshLog]);

  async function evaluateScenario() {
    if (scenario === undefined) return;
    setBusy("evaluate");
    setError(null);
    setDecision(null);
    setReceipt(null);
    setStepUpRequest(null);
    setAuthorization(null);
    setResolutionReason(null);
    setConsumption(null);
    try {
      const issued = await client.issueCredential({
        principal: scenario.principal,
        capabilities: scenario.capabilities,
        expiresAt: future(60),
      });
      const evaluated = await client.evaluate({
        principal: scenario.principal,
        credential: issued.credential,
        action: scenario.action,
        resourceId: scenario.resourceId,
        actionContext: scenario.actionContext,
        policy: scenario.policy,
        issueReceipt: true,
        receiptExpiresAt: future(15),
      });
      setDecision(evaluated.decision);
      setReceipt(evaluated.receipt ?? null);
      if (evaluated.decision.outcome === "STEP_UP") {
        const created = await client.createStepUpRequest({
          decisionLogId: evaluated.logId,
          expiresAt: future(15),
        });
        setStepUpRequest(created.request);
      }
      await refreshLog();
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setBusy(null);
    }
  }

  async function resolveStepUp(resolution: "APPROVE" | "REJECT") {
    if (stepUpRequest === null) return;
    setBusy("resolve");
    setError(null);
    setResolutionReason(null);
    try {
      const approver = {
        id: "principal:reference-approver",
        affiliations: [{ organizationId: "organization:reference", role: "reviewer" }],
      } as const;
      const issued = await client.issueCredential({
        principal: approver,
        capabilities: [stepUpRequest.requiredApproverCapability],
        expiresAt: future(60),
      });
      const resolved = await client.resolveStepUpRequest(stepUpRequest.id, {
        resolution,
        approver,
        approverCredential: issued.credential,
      });
      if (resolved.ok) {
        setAuthorization(resolved.authorization);
        setResolutionReason("STEP_UP_APPROVED");
      } else {
        setAuthorization(null);
        setResolutionReason(resolved.reasonCode);
      }
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setBusy(null);
    }
  }

  async function consumeAuthority() {
    if (decision === null || decision.credentialId === undefined) return;
    setBusy("consume");
    setError(null);
    try {
      if (receipt !== null) {
        const result = await client.consumeReceipt({
          receipt,
          expected: {
            subjectId: decision.subjectId,
            action: decision.action,
            actionSensitivity: decision.actionSensitivity,
            resourceId: decision.resourceId,
            contextHash: decision.contextHash,
            policyId: decision.policyId,
            policyVersion: decision.policyVersion,
            credentialId: decision.credentialId,
            decision: decision.outcome,
            reasonCode: decision.reasonCode,
          },
        });
        setConsumption(result.reasonCode);
      } else if (authorization !== null) {
        const result = await client.consumeStepUpAuthorization({
          authorization,
          subjectId: decision.subjectId,
          action: decision.action,
          actionSensitivity: decision.actionSensitivity,
          resourceId: decision.resourceId,
          contextHash: decision.contextHash,
          policyId: decision.policyId,
          policyVersion: decision.policyVersion,
          credentialId: decision.credentialId,
        });
        setConsumption(result.authorized ? "STEP_UP_AUTHORIZATION_CONSUMED" : "STEP_UP_AUTHORIZATION_REJECTED");
      }
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setBusy(null);
    }
  }

  const canConsume = receipt !== null || authorization !== null;

  return (
    <main>
      <header className="hero">
        <div>
          <p className="eyebrow">ORDIN · zKYC Core</p>
          <h1>Authority Reference Cockpit</h1>
          <p className="lede">Inspect deterministic action-authority decisions from request to one-time consumption.</p>
        </div>
        <div className="boundary" role="note" aria-label="Reference boundary">
          <strong>REFERENCE ONLY</strong>
          <span>Not KYC, ZK verification, production authentication, or action execution.</span>
        </div>
      </header>

      <section className="panel scenario-panel" aria-labelledby="scenario-heading">
        <div className="section-heading">
          <div>
            <p className="step">01 · REQUEST</p>
            <h2 id="scenario-heading">Select a deterministic case</h2>
          </div>
          <button className="primary" type="button" onClick={() => void evaluateScenario()} disabled={busy !== null}>
            {busy === "evaluate" ? "Evaluating…" : "Evaluate authority"}
          </button>
        </div>
        <div className="scenario-grid">
          {scenarios.map((candidate) => (
            <label className={candidate.id === scenarioId ? "scenario selected" : "scenario"} key={candidate.id}>
              <input
                type="radio"
                name="scenario"
                value={candidate.id}
                checked={candidate.id === scenarioId}
                onChange={() => setScenarioId(candidate.id)}
              />
              <span className={`outcome ${candidate.outcome.toLowerCase()}`}>{candidate.outcome}</span>
              <strong>{candidate.label}</strong>
              <small>{candidate.summary}</small>
            </label>
          ))}
        </div>
      </section>

      {error !== null && <p className="error" role="alert">{error}</p>}

      <div className="work-grid">
        <section className="panel" aria-labelledby="decision-heading">
          <p className="step">02 · DECISION</p>
          <h2 id="decision-heading">Reason-coded result</h2>
          {decision === null ? (
            <p className="empty">Evaluate a case to inspect its bound decision.</p>
          ) : (
            <div className="decision-card">
              <span className={`outcome large ${decision.outcome.toLowerCase()}`}>{decision.outcome}</span>
              <dl>
                <div><dt>Reason</dt><dd>{decision.reasonCode}</dd></div>
                <div><dt>Action</dt><dd>{decision.action}</dd></div>
                <div><dt>Tier</dt><dd>{decision.actionSensitivity}</dd></div>
                <div><dt>Resource</dt><dd>{decision.resourceId}</dd></div>
                <div><dt>Policy</dt><dd>{decision.policyId}</dd></div>
                <div><dt>Context</dt><dd className="hash">{decision.contextHash}</dd></div>
              </dl>
            </div>
          )}
        </section>

        <section className="panel" aria-labelledby="resolution-heading">
          <p className="step">03 · RESOLUTION</p>
          <h2 id="resolution-heading">Human boundary</h2>
          {stepUpRequest === null ? (
            <p className="empty">Only STEP_UP cases open a human resolution request.</p>
          ) : (
            <div>
              <p className="request-id">{stepUpRequest.id}</p>
              <div className="button-row">
                <button
                  type="button"
                  onClick={() => void resolveStepUp("APPROVE")}
                  disabled={busy !== null || resolutionReason !== null}
                >Approve</button>
                <button
                  className="secondary"
                  type="button"
                  onClick={() => void resolveStepUp("REJECT")}
                  disabled={busy !== null || resolutionReason !== null}
                >Reject</button>
              </div>
              {resolutionReason !== null && <p className="result-line">{resolutionReason}</p>}
            </div>
          )}
        </section>

        <section className="panel" aria-labelledby="consume-heading">
          <p className="step">04 · CONSUMPTION</p>
          <h2 id="consume-heading">One-time authority</h2>
          <p className="empty">Verification and nonce consumption happen before any downstream handoff. No protected action runs here.</p>
          <button type="button" onClick={() => void consumeAuthority()} disabled={!canConsume || busy !== null}>
            {busy === "consume" ? "Consuming…" : "Verify and consume once"}
          </button>
          {consumption !== null && <p className="result-line">{consumption}</p>}
        </section>
      </div>

      <section className="panel log-panel" aria-labelledby="log-heading">
        <div className="section-heading">
          <div>
            <p className="step">05 · REFERENCE LOG</p>
            <h2 id="log-heading">Reason-coded in-memory entries</h2>
          </div>
          <button className="secondary" type="button" onClick={() => void refreshLogSafely()} disabled={busy !== null}>Refresh</button>
        </div>
        <p className="log-boundary">Defensive-copy reference records only—not durable or distributed audit storage.</p>
        {entries.length === 0 ? (
          <p className="empty">No decisions recorded in this process.</p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead><tr><th>ID</th><th>Outcome</th><th>Reason</th><th>Receipt</th><th>Action</th><th>Policy</th></tr></thead>
              <tbody>
                {entries.map((entry) => (
                  <tr key={entry.id}>
                    <td>{entry.id}</td>
                    <td><span className={`outcome ${entry.decision.outcome.toLowerCase()}`}>{entry.decision.outcome}</span></td>
                    <td>{entry.decision.reasonCode}</td>
                    <td>{entry.receipt === undefined ? "—" : "HMAC summary"}</td>
                    <td>{entry.decision.action}</td>
                    <td>{entry.decision.policyId}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </main>
  );
}
