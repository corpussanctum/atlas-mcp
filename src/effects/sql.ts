import { isAbsolute, dirname, resolve } from "node:path";
import { canonical, sha3 } from "../canonical.js";
import type { AuthorizeRequest, AuthorizeResult, Decision, Effect } from "../engine.js";
import type { Grant } from "../grants.js";
import { DEFAULT_ENFORCEMENT, type EffectAttestation, type EnforcementConfig } from "./contract.js";

/**
 * Reference SQL effect-derivation adapter (F2).
 *
 * This is deliberately stdlib-only and conservative. It derives the action and
 * effects from SQL itself; caller-supplied declarations are never accepted. The
 * same canonical target used for authorization is handed to the executor, and
 * the executor owns connection lifecycle (one fresh connection per call).
 */
export const SQL_EFFECTS_OBSERVER = "atlas-sql-effects/1.0.0";

const READ_VERBS = new Set(["SELECT", "PRAGMA", "EXPLAIN", "VALUES", "WITH"]);
const WRITE_VERBS = new Set(["INSERT", "UPDATE", "REPLACE", "CREATE", "ALTER"]);
const DELETE_VERBS = new Set(["DELETE", "DROP", "TRUNCATE"]);
const ATTACH_VERBS = new Set(["ATTACH", "DETACH"]);
const SEVERITY: Record<string, number> = { "db.read": 1, "db.write": 2, "db.delete": 3 };

export type SqlAction = "db.read" | "db.write" | "db.delete";

export interface DerivationInput {
  sql: string;
  environment: string;
  database: string;
  dbRoot: string;
}

export type DerivationResult =
  | {
      ok: true;
      action: SqlAction;
      effects: Effect[];
      statement: string;
      verbs: string[];
      canonicalTarget: string;
      resource: string;
      environment: string;
      operation_hash: string;
    }
  | { ok: false; decision: "broker_deny"; reason: string };

/** Strip -- and /* *\/ comments without touching quoted literals. */
export function stripSqlComments(sql: string): string {
  let out = "";
  let quote: string | null = null;
  for (let i = 0; i < sql.length; i++) {
    const c = sql[i];
    const n = sql[i + 1];
    if (quote) {
      out += c;
      if (c === quote) {
        if (n === quote) { out += n; i++; } else quote = null;
      }
      continue;
    }
    if (c === "'" || c === '"' || c === "`") { quote = c; out += c; continue; }
    if (c === "-" && n === "-") {
      i += 2;
      while (i < sql.length && sql[i] !== "\n") i++;
      out += "\n";
      continue;
    }
    if (c === "/" && n === "*") {
      i += 2;
      while (i < sql.length && !(sql[i] === "*" && sql[i + 1] === "/")) i++;
      i++; // consume the closing '/'
      out += " ";
      continue;
    }
    out += c;
  }
  return out;
}

/** Replace quoted values with '' so keywords inside strings cannot be classified. */
export function stripSqlLiterals(sql: string): string {
  let out = "";
  let quote: string | null = null;
  for (let i = 0; i < sql.length; i++) {
    const c = sql[i];
    const n = sql[i + 1];
    if (quote) {
      if (c === quote) {
        if (n === quote) { i++; } else quote = null; // the placeholder already represents the quote
      }
      continue;
    }
    if (c === "'" || c === '"') { quote = c; out += "''"; continue; }
    out += c;
  }
  return out;
}

/** Quote-aware split on semicolons; empty statements are dropped. */
export function splitStatements(sql: string): string[] {
  const statements: string[] = [];
  let current = "";
  let quote: string | null = null;
  for (let i = 0; i < sql.length; i++) {
    const c = sql[i];
    if (quote) {
      current += c;
      if (c === quote) {
        if (sql[i + 1] === quote) { current += sql[i + 1]; i++; } else quote = null;
      }
      continue;
    }
    if (c === "'" || c === '"' || c === "`") { quote = c; current += c; continue; }
    if (c === ";") {
      if (current.trim()) statements.push(current.trim());
      current = "";
      continue;
    }
    current += c;
  }
  if (current.trim()) statements.push(current.trim());
  return statements;
}

const ENV_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]*$/;
const DB_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]*\.db$/;

/** Resolve a plain `<root>/<environment>/<name>.db` target; never follow `..` or a linked dir. */
export function canonicalizeTarget(input: { dbRoot: string; environment: string; database: string }):
  | { ok: true; target: string; resource: string }
  | { ok: false; reason: string } {
  const { dbRoot, environment, database } = input;
  if (!ENV_RE.test(environment)) return { ok: false, reason: "environment must be a plain identifier" };
  if (!DB_RE.test(database) || database.includes("..") || database.includes("/") || database.includes("\\")) {
    return { ok: false, reason: "database must be a plain .db filename (no paths or '..')" };
  }
  const base = resolve(dbRoot, environment);
  const target = resolve(base, database);
  if (dirname(target) !== base || isAbsolute(database)) return { ok: false, reason: "database resolves outside its environment directory" };
  return { ok: true, target, resource: `sqlite://${environment}/${database}` };
}

function classify(statement: string):
  | { ok: true; action: SqlAction; verbs: string[] }
  | { ok: false; reason: string } {
  const scan = stripSqlLiterals(statement).toUpperCase();
  const words = scan.match(/\b[A-Za-z_]+\b/g) ?? [];
  if (words.some((w) => ATTACH_VERBS.has(w))) return { ok: false, reason: "ATTACH/DETACH is not mediated; use a fresh connection per call" };
  const verbs = [...new Set(words.filter((w) => READ_VERBS.has(w) || WRITE_VERBS.has(w) || DELETE_VERBS.has(w)))];
  if (!verbs.length) return { ok: false, reason: "unclassified SQL; refusing to guess an action" };
  const action = verbs.reduce<SqlAction>((best, v) => {
    const candidate: SqlAction = DELETE_VERBS.has(v) ? "db.delete" : WRITE_VERBS.has(v) ? "db.write" : "db.read";
    return SEVERITY[candidate] > SEVERITY[best] ? candidate : best;
  }, "db.read");
  return { ok: true, action, verbs };
}

/**
 * Derive an exact, operation-bound declaration. No I/O and no execution: safe
 * to call exhaustively in tests and conformance suites.
 */
export function deriveSqlEffects(input: DerivationInput): DerivationResult {
  if (typeof input.sql !== "string" || !input.sql.trim()) return { ok: false, decision: "broker_deny", reason: "empty SQL statement" };
  const target = canonicalizeTarget(input);
  if (!target.ok) return { ok: false, decision: "broker_deny", reason: target.reason };

  const statements = splitStatements(stripSqlComments(input.sql));
  if (!statements.length) return { ok: false, decision: "broker_deny", reason: "empty SQL statement" };
  if (statements.length > 1) return { ok: false, decision: "broker_deny", reason: `multi-statement SQL is not mediated (${statements.length} statements)` };
  const statement = statements[0];
  const kind = classify(statement);
  if (!kind.ok) return { ok: false, decision: "broker_deny", reason: kind.reason };

  const effects: Effect[] = [{
    type: kind.action.split(".")[1],
    resource: target.resource,
    environment: input.environment,
  }];
  return {
    ok: true,
    action: kind.action,
    effects,
    statement,
    verbs: kind.verbs,
    canonicalTarget: target.target,
    resource: target.resource,
    environment: input.environment,
    operation_hash: sha3(canonical({ statement, canonical_target: target.target, action: kind.action, effects })),
  };
}

type SuccessfulDerivation = Extract<DerivationResult, { ok: true }>;

/** Build the authorize call an enforcement point should send to Atlas. */
export function buildAuthorizationRequest(
  d: SuccessfulDerivation,
  ids: { agent: string; principal: string; delegation_chain: Array<string | Grant> },
  observer: string = SQL_EFFECTS_OBSERVER,
): AuthorizeRequest {
  return {
    agent: ids.agent,
    principal: ids.principal,
    requested_action: d.action,
    effects: d.effects,
    delegation_chain: ids.delegation_chain,
    enforcement: { mode: "observed", observer, operation_hash: d.operation_hash },
  };
}

export interface SqlExecutionResult {
  rows: unknown[];
  /** Effects from an independent source (e.g. fixture _truth triggers). May be empty. */
  observedEffects: Effect[];
  observedAt?: string;
  signature?: string;
}

export interface SqlExecutionInput {
  target: string;
  statement: string;
  operation_hash: string;
  receipt_id: string;
}

export type SqlExecutor = (input: SqlExecutionInput) => SqlExecutionResult | Promise<SqlExecutionResult>;

export interface MediatorAuthority {
  authorize(req: AuthorizeRequest): AuthorizeResult;
  commit(p: {
    receipt_id: string;
    outcome: "success" | "failure";
    attestation: EffectAttestation;
    note?: string;
  }): { status: string; violations: Effect[]; [key: string]: unknown };
}

export interface MediationInput extends DerivationInput {
  agent: string;
  principal: string;
  delegation_chain: Array<string | Grant>;
}

export interface MediationResult {
  ok: boolean;
  decision: Decision | "broker_deny";
  reason: string;
  action?: SqlAction;
  effects?: Effect[];
  executed: boolean;
  rows: unknown[];
  observed_effects: Effect[];
  receipt_id?: string;
  commit?: Record<string, unknown>;
  fail_closed?: boolean;
}

/**
 * Guarded one-call flow: derive -> authorize -> execute -> observe -> commit.
 * `effects` from the caller are never consulted. A missing authority fails
 * closed, and only a permit reaches the executor.
 */
export async function runSqlGuarded(
  input: MediationInput,
  opts: {
    authority?: MediatorAuthority;
    executor: SqlExecutor;
    observer?: string;
    note?: string;
  },
): Promise<MediationResult> {
  const deny = (decision: MediationResult["decision"], reason: string, fail_closed = false): MediationResult =>
    ({ ok: false, decision, reason, executed: false, rows: [], observed_effects: [], fail_closed });

  if (!opts.authority) return deny("broker_deny", "authority is not configured; database action denied (fail closed)", true);
  const d = deriveSqlEffects(input);
  if (!d.ok) return deny(d.decision, d.reason);

  const observer = opts.observer ?? SQL_EFFECTS_OBSERVER;
  const auth = opts.authority.authorize(buildAuthorizationRequest(d, input, observer));
  if (auth.decision !== "permit") return {
    ok: false,
    decision: auth.decision,
    reason: auth.reason,
    action: d.action,
    effects: d.effects,
    executed: false,
    rows: [],
    observed_effects: [],
    receipt_id: auth.receipt_id,
  };

  let execution: SqlExecutionResult;
  try {
    execution = await opts.executor({
      target: d.canonicalTarget,
      statement: d.statement,
      operation_hash: d.operation_hash,
      receipt_id: auth.receipt_id,
    });
  } catch (err) {
    execution = { rows: [], observedEffects: [], observedAt: new Date().toISOString() };
    return {
      ok: false,
      decision: "permit",
      reason: `execution failed: ${(err as Error).message}`,
      action: d.action,
      effects: d.effects,
      executed: false,
      rows: [],
      observed_effects: [],
      receipt_id: auth.receipt_id,
    };
  }

  const observed = Array.isArray(execution.observedEffects) ? execution.observedEffects : [];
  const attestation: EffectAttestation = {
    observer,
    operation_hash: d.operation_hash,
    effects: observed,
    observed_at: execution.observedAt ?? new Date().toISOString(),
    ...(execution.signature ? { signature: execution.signature } : {}),
  };
  let commit: { status: string; violations: Effect[]; [key: string]: unknown };
  try {
    commit = opts.authority.commit({
      receipt_id: auth.receipt_id,
      outcome: "success",
      attestation,
      note: opts.note,
    });
  } catch (err) {
    return {
      ok: false,
      decision: "permit",
      reason: `commit failed: ${(err as Error).message}`,
      action: d.action,
      effects: d.effects,
      executed: true,
      rows: execution.rows,
      observed_effects: observed,
      receipt_id: auth.receipt_id,
    };
  }
  return {
    ok: commit.status !== "violation",
    decision: "permit",
    reason: commit.status,
    action: d.action,
    effects: d.effects,
    executed: true,
    rows: execution.rows,
    observed_effects: observed,
    receipt_id: auth.receipt_id,
    commit,
  };
}

/** Convenience: server policy that requires observed contracts from this adapter. */
export function sqlEnforcementConfig(): EnforcementConfig {
  return { ...DEFAULT_ENFORCEMENT, mode: "observed", trustedObservers: [SQL_EFFECTS_OBSERVER] };
}
