import { canonical, sha3 } from "./canonical.js";
import { canonicalAction, matchAction } from "./actions.js";
import { matchAny } from "./glob.js";
import { verifyChain, type Grant } from "./grants.js";
import type { AuditEntry, AuditLog } from "./audit.js";
import { verifyObserverSignature, type Issuer } from "./keys.js";
import {
  attestationPayload,
  effectCovers,
  OPERATION_HASH_RE,
  type Effect,
  type EffectAttestation,
  type EnforcementConfig,
  type EnforcementContract,
} from "./effects/contract.js";

export type { Effect } from "./effects/contract.js";

export interface AuthorizeRequest {
  agent: string;
  principal: string;
  requested_action: string;
  effects: Effect[];
  delegation_chain: Array<string | Grant>;
  /** Optional F1 contract. Unset means legacy declared-effects behaviour. */
  enforcement?: EnforcementContract;
}

export type Decision = "permit" | "deny" | "escalate";

export interface AuthorizeResult {
  decision: Decision;
  reason: string;
  scope: string;
  receipt_id: string;
  expires_at?: string;
}

export const RECEIPT_TTL_MS = 15 * 60_000;

export class Engine {
  constructor(
    private readonly issuer: Issuer,
    readonly log: AuditLog,
    private readonly enforcement: Readonly<EnforcementConfig> = {},
  ) {}

  authorize(req: AuthorizeRequest, now = new Date()): AuthorizeResult {
    const contractProblem = this.validateContract(req.enforcement);
    const [decision, reason, scope] = contractProblem
      ? (["deny", contractProblem, "none"] as const)
      : this.decide(req, now);
    const expires = decision === "deny" ? undefined : new Date(now.getTime() + RECEIPT_TTL_MS).toISOString();
    const entry = this.log.append("AUTHORIZE", {
      agent: req.agent,
      principal: req.principal,
      requested_action: req.requested_action,
      canonical_action: canonicalAction(req.requested_action) ?? null,
      effects: req.effects,
      effects_hash: sha3(canonical(req.effects)),
      chain: req.delegation_chain.map((g) => (typeof g === "string" ? g : g.id)),
      decision,
      reason,
      scope,
      expires_at: expires,
      ...(req.enforcement ? { enforcement: req.enforcement } : {}),
    });
    return { decision, reason, scope, receipt_id: receiptId(entry), expires_at: expires };
  }

  /** Contracts are checked before policy: a malformed observed receipt is never issued. */
  private validateContract(contract?: EnforcementContract): string | undefined {
    if (!contract) {
      return this.enforcement.mode === "observed"
        ? "an observed enforcement contract (observer + operation_hash) is required by server policy"
        : undefined;
    }
    if (contract.mode !== "declared" && contract.mode !== "observed") return "enforcement.mode must be declared or observed";
    if (this.enforcement.mode === "observed" && contract.mode !== "observed") return "server policy requires mode 'observed'";
    if (contract.mode !== "observed") return undefined;
    if (typeof contract.observer !== "string" || !contract.observer.trim()) return "observed enforcement requires an observer id";
    if (typeof contract.operation_hash !== "string" || !OPERATION_HASH_RE.test(contract.operation_hash)) {
      return "observed enforcement requires operation_hash (64 lowercase hex characters)";
    }
    const trusted = this.enforcement.trustedObservers;
    if (trusted?.length && !trusted.includes(contract.observer)) {
      return `observer '${contract.observer}' is not in the configured trusted observer list`;
    }
    return undefined;
  }

  private decide(req: AuthorizeRequest, now: Date): [Decision, string, string] {
    const bad = validateShape(req);
    if (bad) return ["deny", bad, "none"];

    const verified = verifyChain(this.issuer, this.log, req.principal, req.agent, req.delegation_chain, now);
    if (!verified.ok) return ["deny", verified.reason, "none"];
    const { chain } = verified;
    const scope = describeScope(chain);
    // validateShape guarantees this; actions are matched in canonical form so a
    // case or whitespace variant cannot slip past a deny rule (F3).
    const action = canonicalAction(req.requested_action)!;

    // Authority is the intersection of every link: each one must independently allow the request.
    let escalateReason: string | undefined;
    for (const g of chain) {
      const s = g.scope;
      const denied = s.deny && matchAction(s.deny, action);
      if (denied) return ["deny", `action '${action}' is explicitly denied by grant ${g.id} (deny: ${denied})`, scope];
      if (!matchAction(s.allow, action)) {
        return ["deny", `action '${action}' is not delegated by grant ${g.id} (allows: ${s.allow.join(", ")})`, scope];
      }
      // Fail closed: a restricted grant can only be checked against declared effects.
      if (req.effects.length === 0 && (s.environments || s.resources)) {
        const what = [s.environments && "environments", s.resources && "resources"].filter(Boolean).join(" and ");
        return ["deny", `no effects were declared, but grant ${g.id} restricts ${what}; declare every effect so it can be checked`, scope];
      }
      for (const e of req.effects) {
        if (s.environments) {
          if (!e.environment) return ["deny", `effect on '${e.resource}' has no environment, but grant ${g.id} restricts environments to ${s.environments.join(", ")}`, scope];
          if (!s.environments.includes(e.environment)) {
            return ["deny", `effect targets environment '${e.environment}'; delegated authority (grant ${g.id}) only permits ${s.environments.join(", ")}`, scope];
          }
        }
        if (s.resources && !matchAny(s.resources, e.resource)) {
          return ["deny", `resource '${e.resource}' is outside the scope of grant ${g.id} (${s.resources.join(", ")})`, scope];
        }
      }
      const esc = s.escalate && matchAction(s.escalate, action);
      if (esc && !escalateReason) escalateReason = `action '${action}' requires human approval under grant ${g.id} (escalate: ${esc})`;
    }
    if (escalateReason) return ["escalate", escalateReason, scope];
    return ["permit", `authorized by ${chain.length}-link delegation chain from ${req.principal}`, scope];
  }

  /** Record a human decision on an escalated receipt. */
  resolve(receipt: string, outcome: "approve" | "reject", by: string, note?: string): AuditEntry {
    const auth = this.findAuthorize(receipt);
    if (!auth) throw new Error(`unknown receipt ${receipt}`);
    if (auth.data.decision !== "escalate") throw new Error(`receipt ${receipt} is '${auth.data.decision}', not escalate`);
    if (this.findResolve(receipt)) throw new Error(`receipt ${receipt} was already resolved`);
    return this.log.append("RESOLVE", { receipt_id: receipt, outcome, by, note });
  }

  status(receipt: string, now = new Date()): Record<string, unknown> {
    const auth = this.findAuthorize(receipt);
    if (!auth) return { found: false };
    const d = auth.data;
    const res = this.findResolve(receipt);
    const commit = this.findCommit(receipt);
    let state: string;
    let invalid_reason: string | undefined;
    if (d.decision === "deny") state = "denied";
    else if (commit) state = "committed";
    else if (res?.data.outcome === "reject") state = "rejected";
    else {
      // A receipt is only as good as the authority behind it: re-check the chain as it stands now.
      const chain = verifyChain(this.issuer, this.log, d.principal as string, d.agent as string, d.chain as string[], now);
      if (!chain.ok) {
        state = chain.code === "expired" ? "expired" : "revoked";
        invalid_reason = chain.reason;
      } else if (d.decision === "escalate" && !res) state = "pending_approval";
      else if (now > new Date(d.expires_at as string)) state = "expired";
      else state = "ready";
    }
    return { found: true, state, decision: d.decision, reason: d.reason, scope: d.scope, expires_at: d.expires_at, resolution: res?.data, ...(invalid_reason ? { invalid_reason } : {}) };
  }

  /**
   * Report what was actually done under a receipt; flags effects the receipt never covered.
   *
   * `late` is for an enforcement point (the hook) reporting an action that has
   * already run: the record must not be lost because the receipt expired or its
   * grant was revoked while the action was running. The state is recorded, and
   * a commit under revoked authority counts as a violation.
   */
  commit(p: {
    receipt_id: string;
    outcome: "success" | "failure";
    effects?: Effect[];
    note?: string;
    late?: boolean;
    /** Required when the receipt carries an observed enforcement contract. */
    attestation?: EffectAttestation;
  }, now = new Date()) {
    // The receipt state check and the append share one audit-lock critical
    // section, so two processes cannot both observe `ready` and commit (F5).
    let state: string | undefined;
    let violations: Effect[] = [];
    let missing: Effect[] = [];
    let observedBy: string | undefined;
    let operationHash: string | undefined;
    const result = this.log.appendGuarded("COMMIT", () => {
      const auth = this.findAuthorize(p.receipt_id);
      if (!auth) return { error: `unknown receipt ${p.receipt_id}` };
      if (this.findCommit(p.receipt_id)) return { error: `receipt ${p.receipt_id} cannot be committed: state is 'committed'` };
      const st = this.status(p.receipt_id, now).state as string;
      const lateOk = p.late && (st === "expired" || st === "revoked");
      if (st !== "ready" && !lateOk) return { error: `receipt ${p.receipt_id} cannot be committed: state is '${st}'` };

      const authorized = auth.data.effects as Effect[];
      const contract = auth.data.enforcement as EnforcementContract | undefined;
      let observed = p.effects ?? [];
      let attestationData: Record<string, unknown> = {};

      if (contract?.mode === "observed") {
        const att = p.attestation;
        if (!att) return { error: `receipt ${p.receipt_id} requires an observer attestation (F1 contract)` };
        if (att.observer !== contract.observer) return { error: `attestation observer '${att.observer}' does not match receipt observer '${contract.observer}'` };
        if (att.operation_hash !== contract.operation_hash) return { error: `attestation operation_hash does not match the receipt` };
        if (!Array.isArray(att.effects)) return { error: "attestation.effects must be an array (use [] when nothing was observed)" };
        const trusted = this.enforcement.trustedObservers;
        if (trusted?.length && !trusted.includes(att.observer)) return { error: `observer '${att.observer}' is not trusted by server policy` };
        const publicKey = this.enforcement.observerPublicKeys?.[att.observer];
        if (publicKey) {
          if (!att.signature) return { error: `observer '${att.observer}' requires a signed attestation` };
          const payload = attestationPayload({ receipt_id: p.receipt_id, ...att });
          if (!verifyObserverSignature(publicKey, payload, att.signature)) return { error: "observer attestation signature is invalid" };
        }
        observed = att.effects;
        observedBy = att.observer;
        operationHash = att.operation_hash;
        // A successful mutation that the observer never saw is as serious as an
        // effect the receipt never covered. Reads are bound by operation_hash:
        // trigger-based observers cannot attest them, so they are not required.
        missing = p.outcome === "success"
          ? authorized.filter((a) => a.type !== "read" && !observed.some((o) => effectCovers(a, o)))
          : [];
        attestationData = {
          observed_by: att.observer,
          operation_hash: att.operation_hash,
          attestation: att,
          missing_effects: missing,
          enforcement_mode: "observed",
        };
      }

      violations = observed.filter((o) => !authorized.some((a) => effectCovers(a, o)));
      state = st;
      return {
        data: {
          receipt_id: p.receipt_id,
          outcome: p.outcome,
          observed_effects: observed,
          violations,
          note: p.note,
          ...(st !== "ready" ? { receipt_state: st } : {}),
          ...attestationData,
        },
      };
    });
    if (result.error) throw new Error(result.error);
    const entry = result.entry!;
    const st = state!;
    return {
      commit_id: `cmt_${entry.hash.slice(0, 16)}`,
      status: violations.length || missing.length || st === "revoked" ? "violation" : "recorded",
      violations,
      audit_seq: entry.seq,
      ...(st !== "ready" ? { receipt_state: st } : {}),
      ...(observedBy ? { observed_by: observedBy, operation_hash: operationHash, missing_effects: missing } : {}),
    };
  }

  /**
   * Uncommitted permits are an alertable state, not a neutral one (F1): a
   * permit with no matching COMMIT may mean the action ran outside Atlas.
   * `olderThanMs` lets monitoring separate in-flight calls from stale receipts.
   */
  pendingPermits(now = new Date(), olderThanMs = 0): Array<Record<string, unknown>> {
    const entries = this.log.read();
    const committed = new Set(entries.filter((e) => e.type === "COMMIT").map((e) => e.data.receipt_id));
    return entries
      .filter((e) => e.type === "AUTHORIZE" && e.data.decision !== "deny" && !committed.has(receiptId(e)))
      .map((e) => {
        const receipt = receiptId(e);
        const st = this.status(receipt, now);
        const contract = e.data.enforcement as EnforcementContract | undefined;
        const issuedAt = new Date(e.data.expires_at as string).getTime() - RECEIPT_TTL_MS;
        const ageMs = Math.max(0, now.getTime() - issuedAt);
        const alert = st.state === "expired" || st.state === "revoked" || (st.state === "ready" && ageMs >= olderThanMs);
        return {
          receipt_id: receipt,
          state: st.state,
          decision: e.data.decision,
          requested_action: e.data.requested_action,
          expires_at: e.data.expires_at,
          age_ms: ageMs,
          enforcement_mode: contract?.mode ?? "declared",
          ...(contract?.observer ? { observer: contract.observer } : {}),
          alert,
        };
      })
      .filter((p) => p.state !== "pending_approval" && p.state !== "rejected");
  }

  private findAuthorize(receipt: string) {
    return this.log.read().find((e) => e.type === "AUTHORIZE" && receiptId(e) === receipt);
  }
  private findResolve(receipt: string) {
    return this.log.read().find((e) => e.type === "RESOLVE" && e.data.receipt_id === receipt);
  }
  private findCommit(receipt: string) {
    return this.log.read().find((e) => e.type === "COMMIT" && e.data.receipt_id === receipt);
  }
}

export function receiptId(e: AuditEntry): string {
  return `rcpt_${e.hash.slice(0, 16)}`;
}

function describeScope(chain: Grant[]): string {
  const leaf = chain[chain.length - 1].scope;
  const parts = [`actions: ${leaf.allow.join(", ")}`];
  const envs = chain.map((g) => g.scope.environments).filter(Boolean) as string[][];
  if (envs.length) parts.push(`environments: ${envs.reduce((a, b) => a.filter((x) => b.includes(x))).join(", ") || "(none)"}`);
  const res = chain.flatMap((g) => g.scope.resources ?? []);
  if (res.length) parts.push(`resources: ${[...new Set(res)].join(", ")}`);
  return `${parts.join("; ")} (${chain.length}-link chain)`;
}

function validateShape(r: AuthorizeRequest): string | undefined {
  const str = (v: unknown) => typeof v === "string" && v.length > 0;
  if (!str(r.agent) || !str(r.principal) || !str(r.requested_action)) return "agent, principal and requested_action are required";
  if (!canonicalAction(r.requested_action)) return "requested_action must be a canonical action name (letters, digits, '.', '-', '_' or '/')";
  if (!Array.isArray(r.effects)) return "effects must be an array (use [] for none)";
  for (const e of r.effects) if (!str(e?.type) || !str(e?.resource)) return "each effect needs a type and a resource";
  if (!Array.isArray(r.delegation_chain)) return "delegation_chain must be an array";
  return undefined;
}
