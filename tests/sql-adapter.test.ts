import { afterEach, beforeEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLog } from "../src/audit.js";
import { Engine, type AuthorizeRequest } from "../src/engine.js";
import { issueGrant, type Grant } from "../src/grants.js";
import { Issuer } from "../src/keys.js";
import {
  deriveSqlEffects,
  runSqlGuarded,
  SQL_EFFECTS_OBSERVER,
  sqlEnforcementConfig,
  stripSqlComments,
  stripSqlLiterals,
  splitStatements,
  type MediationInput,
  type SqlExecutionInput,
} from "../src/effects/sql.js";
import { SQL_CONFORMANCE_CASES, type CaseGrant } from "./conformance/sql-cases.js";

describe("reference SQL effect adapter (F2 conformance)", () => {
  let dir: string;
  let engine: Engine;
  let grants: Record<CaseGrant, Grant>;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "atlas-conformance-"));
    const issuer = Issuer.loadOrCreate(dir);
    const log = new AuditLog(dir, issuer);
    engine = new Engine(issuer, log, sqlEnforcementConfig());
    const scope = (allow: string[]) => ({ allow, environments: ["staging"], resources: ["sqlite://staging/*"] });
    grants = {
      reader_staging: issueGrant(issuer, log, { grantor: "user:tj", subject: "agent:phoenix", scope: scope(["db.read"]), ttlHours: 1 }),
      writer_staging: issueGrant(issuer, log, { grantor: "user:tj", subject: "agent:phoenix", scope: scope(["db.read", "db.write"]), ttlHours: 1 }),
      delete_staging: issueGrant(issuer, log, { grantor: "user:tj", subject: "agent:phoenix", scope: scope(["db.read", "db.delete"]), ttlHours: 1 }),
    };
  });

  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it("strips comments and literals and splits statements without surprising the classifier", () => {
    assert.equal(stripSqlComments("SELECT 1 -- DELETE FROM users\n"), "SELECT 1 \n");
    assert.equal(stripSqlLiterals("SELECT 'DELETE; DROP'"), "SELECT ''");
    assert.deepEqual(splitStatements("SELECT 'a;b'; DELETE FROM users;"), ["SELECT 'a;b'", "DELETE FROM users"]);
  });

  for (const c of SQL_CONFORMANCE_CASES) {
    it(`${c.id}: ${c.description}`, async () => {
      const derived = deriveSqlEffects({
        sql: c.sql, environment: c.environment, database: c.database, dbRoot: join(dir, "db"),
      });
      if (c.deniedByAdapter) {
        assert.equal(derived.ok, false, `${c.id} must be refused by the adapter`);
        if (!derived.ok) assert.match(derived.reason, c.deniedByAdapter);
      } else {
        assert.equal(derived.ok, true, `${c.id} should derive: ${JSON.stringify(derived)}`);
        if (derived.ok) {
          assert.equal(derived.action, c.derived!.action);
          assert.deepEqual(derived.effects, c.derived!.effects);
          assert.match(derived.operation_hash, /^[0-9a-f]{64}$/);
        }
      }

      const authorizations: AuthorizeRequest[] = [];
      const executions: SqlExecutionInput[] = [];
      const authority = {
        authorize: (req: AuthorizeRequest) => { authorizations.push(req); return engine.authorize(req); },
        commit: (p: Parameters<Engine["commit"]>[0]) => engine.commit(p),
      };
      const input: MediationInput = {
        sql: c.sql, environment: c.environment, database: c.database,
        dbRoot: join(dir, "db"),
        // Deliberately misleading caller declarations: the adapter must ignore them.
        agent: "agent:phoenix", principal: "user:tj",
        delegation_chain: [grants[c.grant].id],
      };
      const result = await runSqlGuarded({ ...input, requested_action: "db.read", effects: [] } as MediationInput, {
        authority,
        executor: (x) => {
          executions.push(x);
          if (c.executorError) throw new Error(c.executorError);
          return { rows: [], observedEffects: c.truth ?? [] };
        },
      });

      if (c.deniedByAdapter) {
        assert.equal(authorizations.length, 0, "adapter refusals must happen before Atlas");
        assert.equal(executions.length, 0);
        assert.equal(result.decision, "broker_deny");
        return;
      }
      assert.equal(authorizations.length, 1);
      assert.equal(executions.length, c.executorError ? 1 : c.decision === "permit" ? 1 : 0);
      assert.equal(result.decision, c.decision);
      assert.equal(result.action, c.derived!.action);
      assert.deepEqual(authorizations[0].effects, c.derived!.effects);
      assert.equal(authorizations[0].requested_action, c.derived!.action);
      assert.equal(authorizations[0].enforcement?.mode, "observed");
      assert.equal(authorizations[0].enforcement?.observer, SQL_EFFECTS_OBSERVER);
      if (c.executorError) {
        assert.equal(result.executed, false);
        assert.match(result.reason, /fresh connection/);
        return;
      }
      if (c.decision === "deny") {
        assert.equal(result.executed, false);
        return;
      }
      assert.equal(result.executed, true);
      assert.equal(result.commit?.status, "recorded");
      assert.deepEqual(result.observed_effects, c.truth ?? []);
      const commit = engine.log.read().find((e) => e.type === "COMMIT");
      assert.equal(commit?.data.observed_by, SQL_EFFECTS_OBSERVER);
      assert.equal(commit?.data.operation_hash, authorizations[0].enforcement?.operation_hash);
    });
  }

  it("fails closed when no authority is configured", async () => {
    const result = await runSqlGuarded({
      sql: "SELECT 1", environment: "staging", database: "users.db", dbRoot: join(dir, "db"),
      agent: "agent:phoenix", principal: "user:tj", delegation_chain: [grants.reader_staging.id],
    }, { executor: () => ({ rows: [], observedEffects: [] }) });
    assert.equal(result.decision, "broker_deny");
    assert.equal(result.fail_closed, true);
  });
});
