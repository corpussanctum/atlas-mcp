import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLog } from "../src/audit.js";
import { Engine, type Effect } from "../src/engine.js";
import { issueGrant, revokeGrant, type Scope } from "../src/grants.js";
import { Issuer } from "../src/keys.js";

let dir: string;
let issuer: Issuer;
let log: AuditLog;
let engine: Engine;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "atlas-mcp-test-"));
  issuer = Issuer.loadOrCreate(dir);
  log = new AuditLog(dir, issuer);
  engine = new Engine(issuer, log);
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

const grant = (grantor: string, subject: string, scope: Scope, ttlHours = 8) => issueGrant(issuer, log, { grantor, subject, scope, ttlHours });
const eff = (type: string, environment: string, resource = `db://${environment}/users`): Effect => ({ type, environment, resource });
const ask = (action: string, effects: Effect[], chain: string[], agent = "agent:a", principal = "user:tj") =>
  engine.authorize({ agent, principal, requested_action: action, effects, delegation_chain: chain });

describe("authorize", () => {
  it("permits an in-scope action", () => {
    const g = grant("user:tj", "agent:a", { allow: ["db.*"], environments: ["staging"] });
    const r = ask("db.delete", [eff("delete", "staging")], [g.id]);
    assert.equal(r.decision, "permit");
    assert.match(r.receipt_id, /^rcpt_[0-9a-f]{16}$/);
  });

  it("denies production when only staging is delegated", () => {
    const g = grant("user:tj", "agent:a", { allow: ["db.*"], environments: ["staging"] });
    const r = ask("db.delete", [eff("delete", "production")], [g.id]);
    assert.equal(r.decision, "deny");
    assert.match(r.reason, /production.*only permits staging/);
  });

  it("fails closed when an effect omits its environment under an environment-restricted grant", () => {
    const g = grant("user:tj", "agent:a", { allow: ["db.*"], environments: ["staging"] });
    const r = ask("db.delete", [{ type: "delete", resource: "db://x/users" }], [g.id]);
    assert.equal(r.decision, "deny");
  });

  it("denies an action that is not delegated, and honours explicit deny over allow", () => {
    const g = grant("user:tj", "agent:a", { allow: ["db.*"], deny: ["db.drop"] });
    assert.equal(ask("net.fetch", [], [g.id]).decision, "deny");
    assert.match(ask("db.drop", [], [g.id]).reason, /explicitly denied/);
  });

  it("denies resources outside the resource scope", () => {
    const g = grant("user:tj", "agent:a", { allow: ["db.*"], resources: ["db://staging/*"] });
    assert.equal(ask("db.read", [eff("read", "staging", "db://prod/users")], [g.id]).decision, "deny");
    assert.equal(ask("db.read", [eff("read", "staging")], [g.id]).decision, "permit");
  });

  it("escalates actions marked for approval", () => {
    const g = grant("user:tj", "agent:a", { allow: ["db.*"], escalate: ["db.delete"] });
    assert.equal(ask("db.delete", [], [g.id]).decision, "escalate");
    assert.equal(ask("db.read", [], [g.id]).decision, "permit");
  });

  it("denies with an empty chain and for the wrong principal or agent", () => {
    const g = grant("user:tj", "agent:a", { allow: ["*"] });
    assert.equal(ask("db.read", [], []).decision, "deny");
    assert.match(ask("db.read", [], [g.id], "agent:a", "user:mallory").reason, /not the stated principal/);
    assert.match(ask("db.read", [], [g.id], "agent:b").reason, /not the requesting agent/);
  });

  it("denies expired and revoked grants", () => {
    const g = grant("user:tj", "agent:a", { allow: ["*"] }, 1);
    const later = new Date(Date.now() + 2 * 3_600_000);
    assert.match(engine.authorize({ agent: "agent:a", principal: "user:tj", requested_action: "x", effects: [], delegation_chain: [g.id] }, later).reason, /expired/);
    revokeGrant(log, g.id, "test");
    assert.match(ask("x", [], [g.id]).reason, /revoked/);
  });

  it("rejects a forged inline grant: the issuer-recorded copy wins", () => {
    const real = grant("user:tj", "agent:a", { allow: ["db.read"] });
    const forged = { ...real, scope: { allow: ["*"] } };
    const r = engine.authorize({ agent: "agent:a", principal: "user:tj", requested_action: "db.delete", effects: [], delegation_chain: [forged] });
    assert.equal(r.decision, "deny");
    assert.match(r.reason, /not delegated/);
  });

  it("rejects a grant id that was never issued", () => {
    assert.match(ask("x", [], ["grt_000000000000"]).reason, /unknown grant/);
  });
});

describe("delegation chains", () => {
  it("permits through a two-link chain and applies the intersection", () => {
    const root = grant("user:tj", "agent:orch", { allow: ["db.*"], environments: ["staging", "dev"] });
    const child = grant("agent:orch", "agent:worker", { allow: ["db.read"], environments: ["staging"] });
    assert.equal(ask("db.read", [eff("read", "staging")], [root.id, child.id], "agent:worker").decision, "permit");
    assert.equal(ask("db.delete", [eff("delete", "staging")], [root.id, child.id], "agent:worker").decision, "deny");
    assert.equal(ask("db.read", [eff("read", "dev")], [root.id, child.id], "agent:worker").decision, "deny");
  });

  it("rejects a child grant that widens its parent", () => {
    const root = grant("user:tj", "agent:orch", { allow: ["db.read"], environments: ["staging"] });
    const wide = grant("agent:orch", "agent:worker", { allow: ["db.*"] });
    assert.match(ask("db.read", [], [root.id, wide.id], "agent:worker").reason, /widens its parent/);
    const wideEnv = grant("agent:orch", "agent:worker", { allow: ["db.read"], environments: ["production"] });
    assert.match(ask("db.read", [], [root.id, wideEnv.id], "agent:worker").reason, /widens its parent/);
  });

  it("rejects a broken or reordered chain", () => {
    const a = grant("user:tj", "agent:orch", { allow: ["*"] });
    const b = grant("agent:other", "agent:worker", { allow: ["*"] });
    assert.match(ask("x", [], [a.id, b.id], "agent:worker").reason, /chain broken/);
  });

  it("revoking a parent invalidates the whole chain", () => {
    const root = grant("user:tj", "agent:orch", { allow: ["*"] });
    const child = grant("agent:orch", "agent:worker", { allow: ["*"] });
    revokeGrant(log, root.id, "compromised");
    assert.equal(ask("x", [], [root.id, child.id], "agent:worker").decision, "deny");
  });

  it("caps chain depth", () => {
    const ids = [grant("p", "a1", { allow: ["*"] }).id, grant("a1", "a2", { allow: ["*"] }).id, grant("a2", "a3", { allow: ["*"] }).id, grant("a3", "a4", { allow: ["*"] }).id, grant("a4", "a5", { allow: ["*"] }).id];
    assert.match(ask("x", [], ids, "a5", "p").reason, /depth/);
  });
});

describe("escalation, commit, receipts", () => {
  const setup = () => grant("user:tj", "agent:a", { allow: ["db.*"], escalate: ["db.delete"], environments: ["staging"] });

  it("blocks commit until a human approves, and the agent cannot approve", () => {
    const g = setup();
    const r = ask("db.delete", [eff("delete", "staging")], [g.id]);
    assert.equal(engine.status(r.receipt_id).state, "pending_approval");
    assert.throws(() => engine.commit({ receipt_id: r.receipt_id, outcome: "success" }), /pending_approval/);
    engine.resolve(r.receipt_id, "approve", "tj");
    assert.equal(engine.status(r.receipt_id).state, "ready");
    assert.equal(engine.commit({ receipt_id: r.receipt_id, outcome: "success" }).status, "recorded");
  });

  it("blocks commit after rejection and for denied receipts", () => {
    const g = setup();
    const r = ask("db.delete", [eff("delete", "staging")], [g.id]);
    engine.resolve(r.receipt_id, "reject", "tj");
    assert.throws(() => engine.commit({ receipt_id: r.receipt_id, outcome: "success" }), /rejected/);
    const d = ask("db.delete", [eff("delete", "production")], [g.id]);
    assert.throws(() => engine.commit({ receipt_id: d.receipt_id, outcome: "success" }), /denied/);
  });

  it("allows one commit per receipt and rejects expired receipts", () => {
    const g = grant("user:tj", "agent:a", { allow: ["db.*"] });
    const r = ask("db.read", [eff("read", "staging")], [g.id]);
    engine.commit({ receipt_id: r.receipt_id, outcome: "success" });
    assert.throws(() => engine.commit({ receipt_id: r.receipt_id, outcome: "success" }), /committed/);
    const r2 = ask("db.read", [eff("read", "staging")], [g.id]);
    assert.throws(() => engine.commit({ receipt_id: r2.receipt_id, outcome: "success" }, new Date(Date.now() + 20 * 60_000)), /expired/);
  });

  it("flags effects the receipt never authorized", () => {
    const g = grant("user:tj", "agent:a", { allow: ["db.*"] });
    const r = ask("db.read", [eff("read", "staging")], [g.id]);
    const c = engine.commit({ receipt_id: r.receipt_id, outcome: "success", effects: [eff("read", "staging"), eff("delete", "production", "db://production/users")] });
    assert.equal(c.status, "violation");
    assert.equal(c.violations.length, 1);
  });

  it("refuses to resolve a non-escalated receipt twice", () => {
    const g = setup();
    const ok = ask("db.read", [], [g.id]);
    assert.throws(() => engine.resolve(ok.receipt_id, "approve", "tj"), /not escalate/);
    const e = ask("db.delete", [eff("delete", "staging")], [g.id]);
    engine.resolve(e.receipt_id, "approve", "tj");
    assert.throws(() => engine.resolve(e.receipt_id, "reject", "tj"), /already resolved/);
  });
});

describe("audit log", () => {
  it("verifies, and detects edits, deletions and forged entries", () => {
    const g = grant("user:tj", "agent:a", { allow: ["*"] });
    ask("x", [], [g.id]);
    ask("y", [], [g.id]);
    assert.deepEqual(log.verify(), { valid: true, entries: 3 });

    const original = readFileSync(log.path, "utf-8");
    const lines = original.trim().split("\n");

    writeFileSync(log.path, original.replace('"requested_action":"x"', '"requested_action":"z"'));
    assert.equal(log.verify().valid, false);

    writeFileSync(log.path, [lines[0], lines[2]].join("\n") + "\n");
    assert.equal(log.verify().valid, false);

    // Recomputing hashes without the issuer key still fails on the signature.
    const e = JSON.parse(lines[2]);
    e.signature = JSON.parse(lines[1]).signature;
    writeFileSync(log.path, [lines[0], lines[1], JSON.stringify(e)].join("\n") + "\n");
    assert.equal(log.verify().valid, false);
  });
});
