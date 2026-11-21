# Effect enforcement contract and reference SQL adapter

This document closes two findings from the Phoenix × Atlas database slice:

- **F1:** a permit covers the *declaration*, not the action. A caller could declare `db.read` on staging, delete a production row, and either report nothing or report only the declared effect. Atlas had no way to bind a receipt to an exact operation or to check an independent observation.
- **F2:** there was no reference effect-derivation adapter or conformance suite. Declaration fidelity was left to every integrator, and SQL is easy to misclassify (comments, `WITH … DELETE`, `ATTACH`, path traversal, statement batches).

The default installation is unchanged: `declared` mode keeps v0.1 behaviour. The contract below is opt-in per receipt or required globally by operator policy.

## 1. The contract

### Modes

| mode | Who derives effects? | What commit requires | Legacy compatible |
|---|---|---|---|
| `declared` (default) | Caller, at authorize time | `effects` (may be omitted) | yes — unchanged |
| `observed` | A registered enforcement point, from the operation itself | `attestation` from that observer | opt-in |

An `observed` authorize request carries:

```json
{
  "agent": "agent:phoenix",
  "principal": "user:tj",
  "requested_action": "db.delete",
  "effects": [{ "type": "delete", "resource": "sqlite://staging/users.db", "environment": "staging" }],
  "delegation_chain": ["grt_…"],
  "enforcement": {
    "mode": "observed",
    "observer": "atlas-sql-effects/1.0.0",
    "operation_hash": "<64 hex chars: sha3-256 of the canonical operation>"
  }
}
```

The AUTHORIZE entry stores the contract, so it is covered by the signed audit hash chain. A receipt without a contract remains a legacy receipt.

### Committing an observed receipt

The caller cannot satisfy an observed receipt by reporting effects itself. The enforcement point sends:

```json
{
  "receipt_id": "rcpt_…",
  "outcome": "success",
  "attestation": {
    "observer": "atlas-sql-effects/1.0.0",
    "operation_hash": "<same hash as the receipt>",
    "effects": [{ "type": "delete", "resource": "sqlite://staging/users.db", "environment": "staging" }],
    "observed_at": "2026-11-21T00:00:00.000Z",
    "signature": "<base64 ML-DSA-65, when a public key is configured>"
  }
}
```

Atlas refuses the commit when the observer id or operation hash differs from the receipt, when the observer is not trusted by operator policy, when a configured public key is missing or its signature fails, or when `effects` is not an explicit array. These are hard errors, not soft warnings: a caller that cannot attest gets no clean record.

Reconciliation is symmetric on a successful action:

- observed effect not covered by the declaration → `violations` (as before);
- declared **mutation** (`write`, `delete`, …) not seen by the observer → `missing_effects`;
- either list being non-empty makes `status: "violation"`, and both are written into the signed COMMIT entry.

Read effects are bound by `operation_hash`, not required in the observation: trigger-based database observers can see mutations but not reads. On `outcome: "failure"` no mutation is expected, so `missing_effects` is not raised.

### Uncommitted permits are alertable

`atlas_pending_permits` (MCP) and `atlas-mcp pending [--older-than-ms N]` (CLI) list permitted receipts with no COMMIT, including `ready`, `expired` and `revoked` ones. Each row has `alert`, `age_ms`, `state`, `enforcement_mode` and the observer. The CLI exits 1 when any row alerts, so a scheduler can page on it. This closes the third F1 reporting choice: never committing is no longer indistinguishable from a successful quiet action.

### Observer signatures

Identity alone is not authentication if the agent can speak as the observer. Generate a dedicated keypair with the observer's own account:

```bash
atlas-mcp observer-keygen   # prints public_key_b64 and secret_key_b64
```

Keep the secret with the enforcement point (mode 0600, separate OS user/container). Put the public half in operator-controlled policy:

```json
{
  "mode": "observed",
  "trustedObservers": ["atlas-sql-effects/1.0.0"],
  "observerPublicKeys": {
    "atlas-sql-effects/1.0.0": "<public_key_b64>"
  }
}
```

Load it from `$ATLAS_MCP_DATA_DIR/enforcement.json` or `ATLAS_MCP_ENFORCEMENT` (JSON). The file must not be writable by the agent. `attestationPayload()` in `src/effects/contract.ts` defines the exact signed bytes; `signObserverMessage()` in `src/keys.ts` signs them. When no public key is configured, the observer id is an assertion — rely on process/OS isolation for that trust (see F7 below).

## 2. Reference SQL adapter (F2)

`src/effects/sql.ts` is a stdlib-only, conservative reference implementation. It is exported from the published package (`dist/effects/sql.js`) for integrators.

```ts
import { Engine } from "@corpussanctum/atlas-mcp";
import { runSqlGuarded, sqlEnforcementConfig } from "@corpussanctum/atlas-mcp/dist/effects/sql.js";

const result = await runSqlGuarded(
  {
    sql, environment, database, dbRoot,
    agent: "agent:phoenix", principal: "user:tj", delegation_chain: [grantId],
  },
  {
    authority: engine,
    executor: async ({ target, statement, receipt_id }) => {
      // Open a NEW connection to `target` here. Never reuse a pooled connection
      // across an authorization boundary: an ATTACH alias could survive it.
      // Return rows plus effects from an independent source (fixture triggers,
      // database audit table, WAL) — not a restatement of the declaration.
      return { rows, observedEffects, observedAt: new Date().toISOString() };
    },
  },
);
```

The adapter:

1. Canonicalizes `<dbRoot>/<environment>/<name>.db` and rejects `..`, absolute paths, nested names and symlink escapes **before** authorization. The same resolved path is used for execution.
2. Strips `--` and `/* */` comments outside quoted literals, splits semicolon-delimited statements with quote awareness, and refuses empty batches or more than one statement.
3. Scans **every** verb after removing string literals; unknown verbs fail closed. `SELECT`/`PRAGMA`/`EXPLAIN`/`VALUES`/`WITH` → `db.read`, `INSERT`/`UPDATE`/`REPLACE`/`CREATE`/`ALTER` → `db.write`, `DELETE`/`DROP`/`TRUNCATE` → `db.delete`, strongest wins. `ATTACH`/`DETACH` are refused outright.
4. Builds the `observed` contract with a hash of `{statement, canonical_target, action, effects}`. Caller-supplied `action`/`effects` are ignored.
5. Executes only after `permit`, then commits the executor's independently observed effects with a matching attestation. A missing authority fails closed.

It is intentionally not a SQL parser. Use a full parser for richer dialects, but keep the same contract: derive before authorize, bind the operation, observe independently, attest at commit.

## 3. Conformance suite

`npm test` runs `tests/sql-adapter.test.ts` against the shared matrix in `tests/conformance/sql-cases.ts`. Each case asserts both the pure derivation and the end-to-end decision, including whether execution happened:

| id | family | expected |
|---|---|---|
| B0 | staging read | derived `db.read`, permit, clean commit |
| B0w | authorized staging delete | permit, execution, observed delete |
| B1 | production delete declared as a read | derived `db.delete` on production, deny, no execution |
| B2a | leading comment before `DELETE` | derive `db.delete`, deny |
| B2b | `WITH x AS (SELECT …) DELETE` | derive `db.delete`, deny |
| B3a | `ATTACH` to production | broker refusal before Atlas |
| B3b | insert via an `ATTACH` alias | fresh connection has no alias → execution fails |
| B4 | `../production/users.db` | broker refusal before Atlas |
| B5 | `SELECT 1; DELETE …` | broker refusal before Atlas |
| X1–X5 | literals, unknown verb, empty SQL, `DETACH`, traversal in environment | fail closed |

To certify another adapter, reuse `SQL_CONFORMANCE_CASES` and assert the same outcomes. Publishing an adapter that passes the matrix is what the F2 recommendation asks for; passing does **not** make an adapter a full SQL parser.

## 4. What this does not solve

- **F1 model limit:** in `declared` mode, effects remain caller claims. Even in `observed` mode, the guarantee is conditional on the observer being separate from the agent and on its observations being independent. A compromised observer can attest anything.
- **F7 topology:** run Atlas (issuer, CLI, data dir) as a different OS user/container from the agent. Never mount `issuer.json`, `ATLAS_MCP_DATA_DIR`, the Atlas binary or `npx` into the agent. The OpenShell campaign showed containment with a bearer MCP token, not caller authentication; tokens are capabilities and should be scoped, rotated and kept out of agent-writable files.
- **F8 metadata:** `effects: []`, `irreversible`, and caller identity claims are still declared-only. They are advisory in policy decisions, not enforcement. Grants, signatures and the observer contract are the controls.
- **Read effects:** bound by operation hash rather than independent observation; an observer with no query log cannot prove a read did not happen.
- **Existing hook:** `postHook` still commits caller-visible tool effects in `declared` mode. Point gated database work at the reference adapter (or another observed adapter) to get F1 guarantees for SQL.
