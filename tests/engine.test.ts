import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { appendFileSync, existsSync, mkdtempSync, readdirSync, rmSync, readFileSync, unlinkSync, utimesSync, writeFileSync } from "node:fs";
import { hostname, tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
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

  it("fails closed when no effects are declared under an environment- or resource-restricted grant", () => {
    const env = grant("user:tj", "agent:a", { allow: ["db.*"], environments: ["staging"] });
    const r = ask("db.delete", [], [env.id]);
    assert.equal(r.decision, "deny");
    assert.match(r.reason, /no effects were declared.*restricts environments/);
    const res = grant("user:tj", "agent:a", { allow: ["db.*"], resources: ["db://staging/*"] });
    assert.match(ask("db.delete", [], [res.id]).reason, /no effects were declared.*restricts resources/);
    // The restriction may sit on any link of the chain.
    const root = grant("user:tj", "agent:orch", { allow: ["db.*"], environments: ["staging"] });
    const child = grant("agent:orch", "agent:worker", { allow: ["db.read"] });
    assert.equal(ask("db.read", [], [root.id, child.id], "agent:worker").decision, "deny");
    // An unrestricted grant still permits an action with no effects.
    const open = grant("user:tj", "agent:a", { allow: ["db.*"] });
    assert.equal(ask("db.read", [], [open.id]).decision, "permit");
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

  it("invalidates outstanding receipts when a grant behind them is revoked", () => {
    const g = setup();
    const ready = ask("db.read", [eff("read", "staging")], [g.id]);
    const waiting = ask("db.delete", [eff("delete", "staging")], [g.id]);
    const done = ask("db.read", [eff("read", "staging")], [g.id]);
    engine.commit({ receipt_id: done.receipt_id, outcome: "success" });
    assert.equal(engine.status(ready.receipt_id).state, "ready");

    revokeGrant(log, g.id, "compromised");
    const st = engine.status(ready.receipt_id);
    assert.equal(st.state, "revoked");
    assert.match(st.invalid_reason as string, /was revoked/);
    assert.throws(() => engine.commit({ receipt_id: ready.receipt_id, outcome: "success" }), /state is 'revoked'/);
    // An approval given after the revocation does not bring the receipt back.
    assert.equal(engine.status(waiting.receipt_id).state, "revoked");
    engine.resolve(waiting.receipt_id, "approve", "tj");
    assert.equal(engine.status(waiting.receipt_id).state, "revoked");
    // What was already committed stays committed.
    assert.equal(engine.status(done.receipt_id).state, "committed");
  });

  it("invalidates a receipt when a parent link is revoked or the grant expires", () => {
    const root = grant("user:tj", "agent:orch", { allow: ["db.*"] });
    const child = grant("agent:orch", "agent:worker", { allow: ["db.read"] });
    const r = ask("db.read", [], [root.id, child.id], "agent:worker");
    revokeGrant(log, root.id, "x");
    assert.equal(engine.status(r.receipt_id).state, "revoked");

    const short = grant("user:tj", "agent:a", { allow: ["db.*"] }, 0.1); // six minutes, inside the receipt's fifteen
    const r2 = ask("db.read", [], [short.id]);
    const st = engine.status(r2.receipt_id, new Date(Date.now() + 10 * 60_000));
    assert.equal(st.state, "expired");
    assert.match(st.invalid_reason as string, /expired at/);
  });

  it("records a late commit for an action that already ran, and flags revoked authority", () => {
    const g = grant("user:tj", "agent:a", { allow: ["db.*"] });
    const later = new Date(Date.now() + 20 * 60_000);
    const slow = ask("db.read", [eff("read", "staging")], [g.id]);
    assert.throws(() => engine.commit({ receipt_id: slow.receipt_id, outcome: "success" }, later), /expired/);
    const c = engine.commit({ receipt_id: slow.receipt_id, outcome: "success", effects: [eff("read", "staging")], late: true }, later);
    assert.equal(c.status, "recorded");
    assert.equal(c.receipt_state, "expired");
    assert.equal(log.read().at(-1)?.data.receipt_state, "expired");
    assert.throws(() => engine.commit({ receipt_id: slow.receipt_id, outcome: "success", late: true }, later), /committed/);

    const pulled = ask("db.read", [eff("read", "staging")], [g.id]);
    revokeGrant(log, g.id, "x");
    const v = engine.commit({ receipt_id: pulled.receipt_id, outcome: "success", effects: [eff("read", "staging")], late: true });
    assert.equal(v.status, "violation");
    assert.equal(v.receipt_state, "revoked");

    // late never rescues a receipt that was not usable in the first place.
    const denied = ask("net.fetch", [], [g.id]);
    assert.throws(() => engine.commit({ receipt_id: denied.receipt_id, outcome: "success", late: true }), /denied/);
  });

  it("refuses to resolve a non-escalated receipt twice", () => {
    const g = setup();
    const ok = ask("db.read", [eff("read", "staging")], [g.id]);
    assert.equal(ok.decision, "permit");
    assert.throws(() => engine.resolve(ok.receipt_id, "approve", "tj"), /'permit', not escalate/);
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

describe("audit log: truncation, interrupted writes, corruption", () => {
  const lines = () => readFileSync(log.path, "utf-8").trimEnd().split("\n");
  const seed = () => {
    const g = grant("user:tj", "agent:a", { allow: ["*"] });
    ask("x", [], [g.id]);
    return g;
  };

  it("detects entries removed from the end, and refuses to build on the shortened log", () => {
    const g = seed();
    revokeGrant(log, g.id, "compromised");
    assert.deepEqual(log.verify(), { valid: true, entries: 3 });

    writeFileSync(log.path, lines().slice(0, -1).join("\n") + "\n"); // drop the REVOKE
    const v = log.verify();
    assert.equal(v.valid, false);
    assert.equal(v.broken_at, 3);
    assert.match(v.reason!, /truncated: the signed head is entry 3, but the log holds 2/);
    // The revoked grant must not come back to life: authorize fails closed instead of permitting.
    assert.throws(() => ask("x", [], [g.id]), /integrity check.*truncated/);
    assert.equal(lines().length, 2, "nothing was appended on top of the damage");
  });

  it("detects a rewritten log and a forged head", () => {
    seed();
    const head = readFileSync(log.headPath, "utf-8");
    const forged = JSON.parse(head);
    forged.seq = 1;
    writeFileSync(log.headPath, JSON.stringify(forged));
    assert.match(log.verify().reason!, /audit.head has an invalid signature/);
    writeFileSync(log.headPath, "not json");
    assert.match(log.verify().reason!, /unreadable/);
    writeFileSync(log.headPath, head);
    assert.equal(log.verify().valid, true);
  });

  it("accepts a log that runs ahead of its head (crash between the two writes)", () => {
    const g = seed();
    const earlier = readFileSync(log.headPath, "utf-8");
    ask("y", [], [g.id]);
    writeFileSync(log.headPath, earlier);
    assert.deepEqual(log.verify(), { valid: true, entries: 3 });
    assert.equal(ask("z", [], [g.id]).decision, "permit");
    assert.deepEqual(log.verify(), { valid: true, entries: 4 });
  });

  it("warns about a log with no head (written before the head existed), then adopts one", () => {
    const g = seed();
    unlinkSync(log.headPath);
    const v = log.verify();
    assert.equal(v.valid, true);
    assert.match(v.warning!, /no signed head/);
    ask("y", [], [g.id]);
    assert.ok(existsSync(log.headPath));
    assert.deepEqual(log.verify(), { valid: true, entries: 3 });
  });

  it("survives an interrupted final write and repairs it on the next append", () => {
    const g = seed();
    appendFileSync(log.path, '{"seq":3,"ts":"2026');
    const v = log.verify();
    assert.equal(v.valid, true);
    assert.equal(v.entries, 2);
    assert.match(v.warning!, /incomplete line/);
    assert.equal(ask("y", [], [g.id]).decision, "permit");
    assert.deepEqual(log.verify(), { valid: true, entries: 3 });
    assert.equal(lines().length, 3);
  });

  it("reports an unreadable line instead of crashing, and fails closed", () => {
    const g = seed();
    const [first, second] = lines();
    for (const junk of ["{ not json", "null", '{"seq":2}']) {
      writeFileSync(log.path, [first, junk, second].join("\n") + "\n");
      const v = log.verify();
      assert.equal(v.valid, false, junk);
      assert.equal(v.broken_at, 2, junk);
      assert.match(v.reason!, /line 2 is not a valid audit entry/, junk);
      assert.throws(() => ask("y", [], [g.id]), /corrupt at line 2/, junk);
    }
  });

  it("sees entries appended by another process without re-reading an unchanged file", () => {
    const g = seed();
    const before = log.read();
    assert.equal(log.read(), before, "an unchanged file is not parsed again");
    const other = new AuditLog(dir, issuer);
    other.append("REVOKE", { grant_id: g.id, reason: "from elsewhere" });
    assert.equal(log.read().length, 3);
    assert.match(ask("x", [], [g.id]).reason, /revoked/);
    assert.deepEqual(log.verify(), { valid: true, entries: 4 });
  });
});

describe("audit log: locking and first run", () => {
  const BIN = resolve(dirname(fileURLToPath(import.meta.url)), "..", "src", "index.js");
  const lock = () => join(dir, "audit.lock");

  it("takes over at once from a holder that died, and after a timeout from one it cannot check", () => {
    const g = grant("user:tj", "agent:a", { allow: ["*"] });
    const deadPid = spawnSync(process.execPath, ["-e", ""]).pid;
    writeFileSync(lock(), `${hostname()}:${deadPid}:abc`);
    let t = Date.now();
    assert.equal(ask("x", [], [g.id]).decision, "permit");
    assert.ok(Date.now() - t < 2000, "did not wait out the stale timeout");

    writeFileSync(lock(), "some-other-host:1:abc");
    const old = new Date(Date.now() - 60_000);
    utimesSync(lock(), old, old);
    t = Date.now();
    assert.equal(ask("y", [], [g.id]).decision, "permit");
    assert.ok(Date.now() - t < 2000);
    assert.deepEqual(readdirSync(dir).filter((f) => f.startsWith("audit.lock")), [], "no lock files left behind");
    assert.deepEqual(log.verify(), { valid: true, entries: 3 });
  });

  it("keeps one key and one unbroken chain when several first runs race", async () => {
    const fresh = mkdtempSync(join(tmpdir(), "atlas-mcp-race-"));
    try {
      const run = (i: number) => new Promise<number | null>((done) => {
        const p = spawn(process.execPath, [BIN, "grant", "--principal", "user:tj", "--subject", `agent:${i}`, "--allow", "x"], { env: { ...process.env, ATLAS_MCP_DATA_DIR: fresh }, stdio: "ignore" });
        p.on("exit", done);
      });
      const codes = await Promise.all(Array.from({ length: 8 }, (_, i) => run(i)));
      assert.deepEqual(codes, Array(8).fill(0));
      const check = new AuditLog(fresh, Issuer.loadOrCreate(fresh));
      assert.deepEqual(check.verify(), { valid: true, entries: 8 });
      assert.deepEqual(readdirSync(fresh).sort(), ["audit.head", "audit.jsonl", "issuer.json"]);
    } finally { rmSync(fresh, { recursive: true, force: true }); }
  });
});
