import { randomBytes } from "node:crypto";
import { canonical } from "./canonical.js";
import { covers } from "./glob.js";
import type { AuditLog } from "./audit.js";
import type { Issuer } from "./keys.js";

/** What a grant lets its subject do. Every field narrows; omitted restrictions inherit the parent's. */
export interface Scope {
  /** Action patterns the subject may request (`db.read`, `db.*`, `*`). */
  allow: string[];
  /** Action patterns refused even if `allow` matches. */
  deny?: string[];
  /** Action patterns that need a human to approve before they run. */
  escalate?: string[];
  /** Environments effects may touch (`staging`). Unset: unrestricted by this link. */
  environments?: string[];
  /** Resource patterns effects may touch (`postgres://staging/*`). Unset: unrestricted by this link. */
  resources?: string[];
}

export interface GrantBody {
  id: string;
  /** Who is delegating: the principal for the first link, the parent agent after that. */
  grantor: string;
  /** The agent receiving the authority. */
  subject: string;
  scope: Scope;
  issued_at: string;
  expires_at: string;
}

export interface Grant extends GrantBody {
  issuer_key_id: string;
  signature: string;
}

export const MAX_CHAIN_DEPTH = 4;

export function issueGrant(
  issuer: Issuer,
  log: AuditLog,
  p: { grantor: string; subject: string; scope: Scope; ttlHours: number },
): Grant {
  if (!p.scope.allow?.length) throw new Error("scope.allow must list at least one action pattern");
  const now = new Date();
  const body: GrantBody = {
    id: `grt_${randomBytes(6).toString("hex")}`,
    grantor: p.grantor,
    subject: p.subject,
    scope: p.scope,
    issued_at: now.toISOString(),
    expires_at: new Date(now.getTime() + p.ttlHours * 3_600_000).toISOString(),
  };
  const grant: Grant = { ...body, issuer_key_id: issuer.keyId, signature: issuer.sign(canonical(body)) };
  log.append("GRANT", { grant });
  return grant;
}

export function revokeGrant(log: AuditLog, grantId: string, reason: string): void {
  if (!lookupGrant(log, grantId)) throw new Error(`unknown grant ${grantId}`);
  log.append("REVOKE", { grant_id: grantId, reason });
}

export function lookupGrant(log: AuditLog, id: string): Grant | undefined {
  for (const e of log.read()) if (e.type === "GRANT" && (e.data.grant as Grant).id === id) return e.data.grant as Grant;
  return undefined;
}

export function revokedIds(log: AuditLog): Set<string> {
  return new Set(log.read().filter((e) => e.type === "REVOKE").map((e) => e.data.grant_id as string));
}

export type ChainResult = { ok: true; chain: Grant[] } | { ok: false; reason: string };

/**
 * Resolve and verify a delegation chain (root first). Each entry is a grant id
 * or an inline grant object. The chain must start at `principal`, end at
 * `agent`, link subject-to-grantor with no gaps, carry valid unexpired
 * unrevoked signatures, and never widen scope from one link to the next.
 */
export function verifyChain(
  issuer: Issuer,
  log: AuditLog,
  principal: string,
  agent: string,
  refs: Array<string | Grant>,
  now = new Date(),
): ChainResult {
  if (refs.length === 0) return { ok: false, reason: "empty delegation chain: no authority was delegated to this agent" };
  if (refs.length > MAX_CHAIN_DEPTH) return { ok: false, reason: `delegation chain depth ${refs.length} exceeds max ${MAX_CHAIN_DEPTH}` };

  const revoked = revokedIds(log);
  const chain: Grant[] = [];
  for (const ref of refs) {
    const id = typeof ref === "string" ? ref : ref?.id;
    // Always trust the issuer-recorded copy, never the caller's copy of a grant.
    const g = id ? lookupGrant(log, id) : undefined;
    if (!g) return { ok: false, reason: `unknown grant ${JSON.stringify(id)}` };
    const { issuer_key_id, signature, ...body } = g;
    if (issuer_key_id !== issuer.keyId || !issuer.verify(canonical(body), signature)) return { ok: false, reason: `grant ${g.id} has an invalid signature` };
    if (revoked.has(g.id)) return { ok: false, reason: `grant ${g.id} was revoked` };
    if (now > new Date(g.expires_at)) return { ok: false, reason: `grant ${g.id} expired at ${g.expires_at}` };
    chain.push(g);
  }

  if (chain[0].grantor !== principal) {
    return { ok: false, reason: `chain starts at '${chain[0].grantor}', not the stated principal '${principal}'` };
  }
  for (let i = 1; i < chain.length; i++) {
    if (chain[i].grantor !== chain[i - 1].subject) {
      return { ok: false, reason: `chain broken between ${chain[i - 1].id} (-> ${chain[i - 1].subject}) and ${chain[i].id} (from ${chain[i].grantor})` };
    }
  }
  const leaf = chain[chain.length - 1];
  if (leaf.subject !== agent) return { ok: false, reason: `chain ends at '${leaf.subject}', not the requesting agent '${agent}'` };

  for (let i = 1; i < chain.length; i++) {
    const widened = widening(chain[i - 1].scope, chain[i].scope);
    if (widened) return { ok: false, reason: `grant ${chain[i].id} widens its parent ${chain[i - 1].id}: ${widened}` };
  }
  return { ok: true, chain };
}

/** Describe how `child` grants more than `parent`, or undefined if it only narrows. */
function widening(parent: Scope, child: Scope): string | undefined {
  for (const a of child.allow) {
    if (!parent.allow.some((p) => covers(p, a))) return `action '${a}' not allowed by parent`;
  }
  if (parent.environments && child.environments) {
    const extra = child.environments.find((e) => !parent.environments!.includes(e));
    if (extra) return `environment '${extra}' not allowed by parent`;
  }
  if (parent.resources && child.resources) {
    const extra = child.resources.find((r) => !parent.resources!.some((p) => covers(p, r)));
    if (extra) return `resource '${extra}' not allowed by parent`;
  }
  return undefined;
}
