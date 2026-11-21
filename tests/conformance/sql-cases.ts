import type { Effect } from "../../src/effects/contract.js";

/**
 * Shared F2 conformance matrix. These are the bypass families from the Phoenix
 * Atlas database slice (B0-B5) plus fail-closed cases (X1-X5). Every adapter
 * claiming effect-derivation parity should be run against these cases.
 */
export type CaseGrant = "reader_staging" | "writer_staging" | "delete_staging";

export interface ConformanceCase {
  id: string;
  description: string;
  environment: string;
  database: string;
  sql: string;
  grant: CaseGrant;
  /** Expected pure derivation (omitted when the adapter must refuse before Atlas). */
  derived?: { action: "db.read" | "db.write" | "db.delete"; effects: Effect[] };
  /** Expected broker-level refusal reason. */
  deniedByAdapter?: RegExp;
  /** Expected Atlas decision for a valid derived request. */
  decision?: "permit" | "deny";
  /** Simulate an executor failure (e.g. an ATTACH alias that cannot exist on a fresh connection). */
  executorError?: string;
  truth?: Effect[];
}

const effect = (type: string, environment = "staging"): Effect => ({
  type,
  resource: `sqlite://${environment}/users.db`,
  environment,
});

export const SQL_CONFORMANCE_CASES: ConformanceCase[] = [
  {
    id: "B0",
    description: "positive control: a staging read is derived and permitted",
    environment: "staging", database: "users.db",
    sql: "SELECT id, name FROM users ORDER BY id",
    grant: "reader_staging",
    derived: { action: "db.read", effects: [effect("read")] },
    decision: "permit",
  },
  {
    id: "B0w",
    description: "fidelity guard: an authorized staging delete is executed and observed",
    environment: "staging", database: "users.db",
    sql: "DELETE FROM users WHERE id = 6",
    grant: "delete_staging",
    derived: { action: "db.delete", effects: [effect("delete")] },
    decision: "permit",
    truth: [effect("delete")],
  },
  {
    id: "B1",
    description: "F1 guard: a production delete cannot hide behind a staging read declaration",
    environment: "production", database: "users.db",
    sql: "DELETE FROM users WHERE id = 1",
    grant: "reader_staging",
    derived: { action: "db.delete", effects: [effect("delete", "production")] },
    decision: "deny",
  },
  {
    id: "B2a",
    description: "leading comment cannot defeat verb classification",
    environment: "staging", database: "users.db",
    sql: "/* maintenance */ DELETE FROM users WHERE id = 7",
    grant: "reader_staging",
    derived: { action: "db.delete", effects: [effect("delete")] },
    decision: "deny",
  },
  {
    id: "B2b",
    description: "WITH ... DELETE is classified by every verb, not the first",
    environment: "staging", database: "users.db",
    sql: "WITH x AS (SELECT 1) DELETE FROM users WHERE id = 9",
    grant: "reader_staging",
    derived: { action: "db.delete", effects: [effect("delete")] },
    decision: "deny",
  },
  {
    id: "B3a",
    description: "ATTACH is refused before Atlas; no alias can cross an authorization boundary",
    environment: "staging", database: "users.db",
    sql: "ATTACH DATABASE '/fixture/production/users.db' AS p",
    grant: "writer_staging",
    deniedByAdapter: /ATTACH\/DETACH/,
  },
  {
    id: "B3b",
    description: "an alias-only insert fails on the fresh connection used after authorization",
    environment: "staging", database: "users.db",
    sql: "INSERT INTO p.users(id, name) VALUES (90, 'mallory')",
    grant: "writer_staging",
    derived: { action: "db.write", effects: [effect("write")] },
    decision: "permit",
    executorError: "no such table: p.users on a fresh connection",
  },
  {
    id: "B4",
    description: "path traversal is rejected before the resource string is built",
    environment: "staging", database: "../production/users.db",
    sql: "INSERT INTO users(id, name) VALUES (94, 'eve')",
    grant: "writer_staging",
    deniedByAdapter: /plain \.db filename/,
  },
  {
    id: "B5",
    description: "multi-statement batches are refused before Atlas decides",
    environment: "staging", database: "users.db",
    sql: "SELECT 1; DELETE FROM users WHERE id = 11",
    grant: "reader_staging",
    deniedByAdapter: /multi-statement/,
  },
  {
    id: "X1",
    description: "keywords inside string literals are not verbs",
    environment: "staging", database: "users.db",
    sql: "SELECT 'DELETE FROM users; DROP TABLE users' AS s",
    grant: "reader_staging",
    derived: { action: "db.read", effects: [effect("read")] },
    decision: "permit",
  },
  {
    id: "X2",
    description: "unknown verbs fail closed instead of defaulting to read",
    environment: "staging", database: "users.db",
    sql: "VACUUM",
    grant: "reader_staging",
    deniedByAdapter: /unclassified SQL/,
  },
  {
    id: "X3",
    description: "empty SQL fails closed",
    environment: "staging", database: "users.db",
    sql: "   ;   ",
    grant: "reader_staging",
    deniedByAdapter: /empty SQL/,
  },
  {
    id: "X4",
    description: "DETACH is refused like ATTACH",
    environment: "staging", database: "users.db",
    sql: "DETACH DATABASE p",
    grant: "writer_staging",
    deniedByAdapter: /ATTACH\/DETACH/,
  },
  {
    id: "X5",
    description: "a traversal in the environment name is rejected",
    environment: "../production", database: "users.db",
    sql: "SELECT 1",
    grant: "reader_staging",
    deniedByAdapter: /environment must be a plain identifier/,
  },
];
