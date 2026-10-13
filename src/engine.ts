import { canonical, sha3 } from "./canonical.js";
import { matchAny, matchGlob } from "./glob.js";
import { verifyChain, type Grant } from "./grants.js";
import type { AuditEntry, AuditLog } from "./audit.js";
import type { Issuer } from "./keys.js";

export interface Effect {
  /** read | write | create | delete | exec | send | spend ... free-form */
  type: string;
  /** What is touched, e.g. `postgres://prod/users`. */
  resource: string;
  /** e.g. `staging`, `production`. Required when any grant restricts environments. */
  environment?: string;
  irreversible?: boolean;
}

export interface AuthorizeRequest {
  agent: string;
  principal: string;
  requested_action: string;
  effects: Effect[];
  delegation_chain: Array<string | Grant>;
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
  ) {}

  authorize(req: AuthorizeRequest, now = new Date()): AuthorizeResult {
    const [decision, reason, scope] = this.decide(req, now);
    const expires = decision === "deny" ? undefined : new Date(now.getTime() + RECEIPT_TTL_MS).toISOString();
    const entry = this.log.append("AUTHORIZE", {
      agent: req.agent,
      principal: req.principal,
      requested_action: req.requested_action,
      effects: req.effects,
      effects_hash: sha3(canonical(req.effects)),
      chain: req.delegation_chain.map((g) => (typeof g === "string" ? g : g.id)),
      decision,
      reason,
      scope,
      expires_at: expires,
    });
    return { decision, reason, scope, receipt_id: receiptId(entry), expires_at: expires };
  }

  private decide(req: AuthorizeRequest, now: Date): [Decision, string, string] {
    const bad = validateShape(req);
    if (bad) return ["deny", bad, "none"];

    const verified = verifyChain(this.issuer, this.log, req.principal, req.agent, req.delegation_chain, now);
    if (!verified.ok) return ["deny", verified.reason, "none"];
    const { chain } = verified;
    const scope = describeScope(chain);

    // Authority is the intersection of every link: each one must independently allow the request.
    let escalateReason: string | undefined;
    for (const g of chain) {
      const s = g.scope;
      const denied = s.deny && matchAny(s.deny, req.requested_action);
      if (denied) return ["deny", `action '${req.requested_action}' is explicitly denied by grant ${g.id} (deny: ${denied})`, scope];
      if (!matchAny(s.allow, req.requested_action)) {
        return ["deny", `action '${req.requested_action}' is not delegated by grant ${g.id} (allows: ${s.allow.join(", ")})`, scope];
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
      const esc = s.escalate && matchAny(s.escalate, req.requested_action);
      if (esc && !escalateReason) escalateReason = `action '${req.requested_action}' requires human approval under grant ${g.id} (escalate: ${esc})`;
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
    if (d.decision === "deny") state = "denied";
    else if (commit) state = "committed";
    else if (d.decision === "escalate" && !res) state = "pending_approval";
    else if (res?.data.outcome === "reject") state = "rejected";
    else if (now > new Date(d.expires_at as string)) state = "expired";
    else state = "ready";
    return { found: true, state, decision: d.decision, reason: d.reason, scope: d.scope, expires_at: d.expires_at, resolution: res?.data };
  }

  /** Report what was actually done under a receipt; flags effects the receipt never covered. */
  commit(p: { receipt_id: string; outcome: "success" | "failure"; effects?: Effect[]; note?: string }, now = new Date()) {
    const auth = this.findAuthorize(p.receipt_id);
    if (!auth) throw new Error(`unknown receipt ${p.receipt_id}`);
    const st = this.status(p.receipt_id, now).state as string;
    if (st !== "ready") throw new Error(`receipt ${p.receipt_id} cannot be committed: state is '${st}'`);

    const authorized = auth.data.effects as Effect[];
    const observed = p.effects ?? [];
    const violations = observed.filter((o) => !authorized.some((a) => a.type === o.type && a.environment === o.environment && matchGlob(a.resource, o.resource)));
    const entry = this.log.append("COMMIT", {
      receipt_id: p.receipt_id,
      outcome: p.outcome,
      observed_effects: observed,
      violations,
      note: p.note,
    });
    return {
      commit_id: `cmt_${entry.hash.slice(0, 16)}`,
      status: violations.length ? "violation" : "recorded",
      violations,
      audit_seq: entry.seq,
    };
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
  if (!Array.isArray(r.effects)) return "effects must be an array (use [] for none)";
  for (const e of r.effects) if (!str(e?.type) || !str(e?.resource)) return "each effect needs a type and a resource";
  if (!Array.isArray(r.delegation_chain)) return "delegation_chain must be an array";
  return undefined;
}
