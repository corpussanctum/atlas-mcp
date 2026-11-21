import { afterEach, beforeEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLog } from "../src/audit.js";
import { Engine, type AuthorizeRequest } from "../src/engine.js";
import { issueGrant } from "../src/grants.js";
import { generateObserverKey, Issuer, signObserverMessage } from "../src/keys.js";
import { attestationPayload, type EffectAttestation, type EnforcementConfig } from "../src/effects/contract.js";

describe("F1 enforcement contract", () => {
  let dir: string;
  let issuer: Issuer;
  let log: AuditLog;
  let grantId: string;

  const OBSERVER = "test-observer/1.0.0";
  const HASH = "a".repeat(64);
  const readEffect = { type: "read", resource: "sqlite://staging/users.db", environment: "staging" };
  const writeEffect = { type: "write", resource: "sqlite://staging/users.db", environment: "staging" };

  function open(config: EnforcementConfig = {}): Engine {
    return new Engine(issuer, log, config);
  }

  function request(engine: Engine, effects = [readEffect], enforcement?: AuthorizeRequest["enforcement"]) {
    return engine.authorize({
      agent: "agent:test", principal: "user:tj", requested_action: "db.read",
      effects, delegation_chain: [grantId], ...(enforcement ? { enforcement } : {}),
    });
  }

  function attestation(effects = [readEffect], overrides: Partial<EffectAttestation> = {}): EffectAttestation {
    return { observer: OBSERVER, operation_hash: HASH, effects, observed_at: "2026-11-21T00:00:00.000Z", ...overrides };
  }

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "atlas-contract-"));
    issuer = Issuer.loadOrCreate(dir);
    log = new AuditLog(dir, issuer);
    grantId = issueGrant(issuer, log, {
      grantor: "user:tj", subject: "agent:test",
      scope: { allow: ["db.read", "db.write"], environments: ["staging"], resources: ["sqlite://staging/*"] },
      ttlHours: 1,
    }).id;
  });

  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it("keeps legacy declared-mode commits unchanged", () => {
    const engine = open();
    const r = request(engine);
    assert.equal(r.decision, "permit");
    // Omitted effects used to be a clean commit and must remain one (no new violation).
    assert.equal(engine.commit({ receipt_id: r.receipt_id, outcome: "success" }).status, "recorded");
  });

  it("refuses to commit an observed receipt from caller-reported effects alone", () => {
    const engine = open();
    const r = request(engine, [readEffect], { mode: "observed", observer: OBSERVER, operation_hash: HASH });
    assert.equal(r.decision, "permit");
    assert.throws(
      () => engine.commit({ receipt_id: r.receipt_id, outcome: "success", effects: [readEffect] }),
      /requires an observer attestation/,
    );
  });

  it("rejects a mismatched observer or operation hash", () => {
    const engine = open();
    const r = request(engine, [readEffect], { mode: "observed", observer: OBSERVER, operation_hash: HASH });
    assert.throws(() => engine.commit({ receipt_id: r.receipt_id, outcome: "success", attestation: attestation([], { observer: "other" }) }), /observer/);
    assert.throws(() => engine.commit({ receipt_id: r.receipt_id, outcome: "success", attestation: attestation([], { operation_hash: "b".repeat(64) }) }), /operation_hash/);
  });

  it("records an attested commit with the observer and bound operation", () => {
    const engine = open();
    const r = request(engine, [readEffect], { mode: "observed", observer: OBSERVER, operation_hash: HASH });
    const result = engine.commit({ receipt_id: r.receipt_id, outcome: "success", attestation: attestation() });
    assert.equal(result.status, "recorded");
    assert.equal(result.observed_by, OBSERVER);
    assert.equal(result.operation_hash, HASH);
    const entry = log.read().find((e) => e.type === "COMMIT");
    assert.equal(entry?.data.enforcement_mode, "observed");
    assert.equal(entry?.data.observed_by, OBSERVER);
  });

  it("flags declared mutations the observer never saw", () => {
    const engine = open();
    const r = request(engine, [writeEffect], { mode: "observed", observer: OBSERVER, operation_hash: HASH });
    const result = engine.commit({ receipt_id: r.receipt_id, outcome: "success", attestation: attestation([]) });
    assert.equal(result.status, "violation");
    assert.ok(result.missing_effects);
    assert.equal(result.missing_effects.length, 1);
    assert.deepEqual(result.missing_effects, [writeEffect]);
    const entry = log.read().find((e) => e.type === "COMMIT");
    assert.deepEqual(entry?.data.missing_effects, [writeEffect]);
  });

  it("flags observed effects the declaration never covered", () => {
    const engine = open();
    const r = request(engine, [readEffect], { mode: "observed", observer: OBSERVER, operation_hash: HASH });
    const sneaky = { type: "delete", resource: "sqlite://production/users.db", environment: "production" };
    const result = engine.commit({ receipt_id: r.receipt_id, outcome: "success", attestation: attestation([readEffect, sneaky]) });
    assert.equal(result.status, "violation");
    assert.deepEqual(result.violations, [sneaky]);
  });

  it("requires and verifies an observer signature when a public key is configured", () => {
    const keys = generateObserverKey();
    const engine = open({ observerPublicKeys: { [OBSERVER]: keys.public_key_b64 } });
    const r = request(engine, [readEffect], { mode: "observed", observer: OBSERVER, operation_hash: HASH });
    const att = attestation();
    assert.throws(() => engine.commit({ receipt_id: r.receipt_id, outcome: "success", attestation: att }), /requires a signed attestation/);
    const signature = signObserverMessage(keys.secret_key_b64, attestationPayload({ receipt_id: r.receipt_id, ...att }));
    assert.equal(engine.commit({ receipt_id: r.receipt_id, outcome: "success", attestation: { ...att, signature } }).status, "recorded");
  });

  it("rejects a tampered signature", () => {
    const keys = generateObserverKey();
    const engine = open({ observerPublicKeys: { [OBSERVER]: keys.public_key_b64 } });
    const r = request(engine, [readEffect], { mode: "observed", observer: OBSERVER, operation_hash: HASH });
    const att = attestation();
    const signature = signObserverMessage(keys.secret_key_b64, attestationPayload({ receipt_id: r.receipt_id, ...att }));
    assert.throws(
      () => engine.commit({ receipt_id: r.receipt_id, outcome: "success", attestation: { ...att, signature: `x${signature.slice(1)}` } }),
      /signature is invalid/,
    );
  });

  it("denies untrusted observers and contracts missing an observer at authorize time", () => {
    const engine = open({ trustedObservers: [OBSERVER] });
    assert.match(request(engine, [readEffect], { mode: "observed", observer: "mallory", operation_hash: HASH }).reason, /not in the configured trusted observer list/);
    assert.match(request(engine, [readEffect], { mode: "observed", operation_hash: HASH }).reason, /requires an observer id/);
  });

  it("requires an observed contract when server policy says so", () => {
    const engine = open({ mode: "observed", trustedObservers: [OBSERVER] });
    assert.match(request(engine).reason, /observed enforcement contract .* required/);
    assert.equal(request(engine, [readEffect], { mode: "observed", observer: OBSERVER, operation_hash: HASH }).decision, "permit");
  });

  it("surfaces uncommitted permits as alerts and clears them on commit", () => {
    const engine = open();
    const r = request(engine, [readEffect], { mode: "observed", observer: OBSERVER, operation_hash: HASH });
    const pending = engine.pendingPermits();
    assert.equal(pending.length, 1);
    assert.equal(pending[0].receipt_id, r.receipt_id);
    assert.equal(pending[0].alert, true);
    assert.equal(pending[0].enforcement_mode, "observed");
    assert.equal(pending[0].observer, OBSERVER);
    engine.commit({ receipt_id: r.receipt_id, outcome: "success", attestation: attestation() });
    assert.equal(engine.pendingPermits().length, 0);
  });

  it("marks expired uncommitted permits for monitoring", () => {
    const engine = open();
    const now = new Date("2026-11-21T00:00:00.000Z");
    const r = engine.authorize({
      agent: "agent:test", principal: "user:tj", requested_action: "db.read", effects: [readEffect], delegation_chain: [grantId],
    }, now);
    const later = new Date(now.getTime() + 16 * 60_000);
    const pending = engine.pendingPermits(later, 60_000);
    assert.equal(pending[0].receipt_id, r.receipt_id);
    assert.equal(pending[0].state, "expired");
    assert.equal(pending[0].alert, true);
  });

  it("writes contract fields into the signed audit entry", () => {
    const engine = open();
    const r = request(engine, [readEffect], { mode: "observed", observer: OBSERVER, operation_hash: HASH });
    const entry = log.read().find((e) => e.type === "AUTHORIZE" && e.data.enforcement);
    const enforcement = entry?.data.enforcement as { mode: string; observer: string; operation_hash: string } | undefined;
    assert.equal(enforcement?.mode, "observed");
    assert.equal(enforcement?.observer, OBSERVER);
    assert.equal(enforcement?.operation_hash, HASH);
    assert.equal(log.verify().valid, true);
  });
});
