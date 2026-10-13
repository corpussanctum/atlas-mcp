import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, existsSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { AuditLog } from "../src/audit.js";
import { Engine } from "../src/engine.js";
import { issueGrant } from "../src/grants.js";
import { Issuer } from "../src/keys.js";
import { classify, postHook, preHook, type HookConfig } from "../src/hook.js";

let dir: string;
let engine: Engine;
let cfg: HookConfig;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "atlas-mcp-hook-"));
  const issuer = Issuer.loadOrCreate(dir);
  const log = new AuditLog(dir, issuer);
  engine = new Engine(issuer, log);
  const g = issueGrant(issuer, log, {
    grantor: "user:alice", subject: "agent:cc", ttlHours: 8,
    scope: { allow: ["file.write", "shell.exec", "shell.deploy", "shell.delete"], escalate: ["shell.deploy", "shell.delete"], environments: ["dev", "staging"] },
  });
  cfg = { agent: "agent:cc", principal: "user:alice", delegation_chain: [g.id], default_environment: "dev" };
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

const bash = (command: string, id = "toolu_1") => ({ tool_name: "Bash", tool_input: { command }, tool_use_id: id });
const pre = (input: object) => preHook(input, engine, cfg, dir);

describe("classify", () => {
  it("maps tools to actions and infers environments", () => {
    assert.equal(classify(cfg, "Bash", { command: "ls -la" })?.action, "shell.exec");
    assert.equal(classify(cfg, "Bash", { command: "rm -rf build" })?.action, "shell.delete");
    assert.equal(classify(cfg, "Bash", { command: "kubectl delete pod x -n production" })?.action, "shell.deploy");
    assert.equal(classify(cfg, "Bash", { command: "psql prod -c 'drop table users'" })?.effects[0].environment, "production");
    assert.equal(classify(cfg, "Write", { file_path: "/srv/app/a.ts" })?.action, "file.write");
    assert.equal(classify(cfg, "mcp__github__create_issue", {})?.action, "mcp.github.create_issue");
  });
  it("leaves reads and Atlas's own tools alone", () => {
    assert.equal(classify(cfg, "Read", { file_path: "/etc/passwd" }), null);
    assert.equal(classify(cfg, "mcp__atlas__atlas_authorize", {}), null);
    assert.equal(classify(cfg, "SomethingNew", {}), null);
  });
  it("applies custom rules before built-ins", () => {
    const c = { ...cfg, rules: [{ tool: "^Bash$", match: "^make release", action: "shell.deploy", effect_type: "deploy" }] };
    assert.equal(classify(c, "Bash", { command: "make release" })?.action, "shell.deploy");
  });
});

describe("preHook", () => {
  it("defers on an in-scope command, and can allow when configured", () => {
    assert.equal(pre(bash("npm test")), null);
    cfg.on_permit = "allow";
    assert.equal(pre(bash("npm test"))?.hookSpecificOutput.permissionDecision, "allow");
  });
  it("denies production: the headline scenario", () => {
    const out = pre(bash("psql $PROD_URL -c 'select 1'  # production"));
    assert.equal(out?.hookSpecificOutput.permissionDecision, "deny");
    assert.match(out!.hookSpecificOutput.permissionDecisionReason, /production.*only permits dev, staging/);
  });
  it("asks for destructive actions in an allowed environment", () => {
    const out = pre(bash("rm -rf node_modules"));
    assert.equal(out?.hookSpecificOutput.permissionDecision, "ask");
  });
  it("denies edits to Atlas's own data directory", () => {
    const out = pre({ tool_name: "Edit", tool_input: { file_path: join(dir, "hook.json") }, tool_use_id: "t" });
    assert.equal(out?.hookSpecificOutput.permissionDecision, "deny");
    assert.match(out!.hookSpecificOutput.permissionDecisionReason, /own authority/);
  });
  it("denies when the delegation has been revoked or expired", () => {
    cfg.delegation_chain = ["grt_000000000000"];
    assert.equal(pre(bash("npm test"))?.hookSpecificOutput.permissionDecision, "deny");
  });
});

describe("postHook", () => {
  it("commits a permitted call and clears the pending marker", () => {
    pre(bash("npm test", "t1"));
    assert.ok(postHook({ tool_name: "Bash", tool_use_id: "t1", tool_response: {} }, engine, dir)?.startsWith("rcpt_"));
    assert.equal(engine.log.read().at(-1)?.type, "COMMIT");
    assert.equal(postHook({ tool_name: "Bash", tool_use_id: "t1" }, engine, dir), null);
    assert.deepEqual(readdirSync(join(dir, "hook-pending")), []);
  });
  it("records the user's approval when an escalated call ran, then commits", () => {
    pre(bash("rm -rf dist", "t2"));
    postHook({ tool_name: "Bash", tool_use_id: "t2" }, engine, dir);
    const types = engine.log.read().slice(-3).map((e) => e.type);
    assert.deepEqual(types, ["AUTHORIZE", "RESOLVE", "COMMIT"]);
    assert.equal(engine.log.verify().valid, true);
  });
  it("records failures", () => {
    pre(bash("npm test", "t3"));
    postHook({ tool_name: "Bash", tool_use_id: "t3", hook_event_name: "PostToolUseFailure" }, engine, dir);
    assert.equal(engine.log.read().at(-1)?.data.outcome, "failure");
  });
  it("ignores calls Atlas never saw", () => {
    assert.equal(postHook({ tool_name: "Bash", tool_use_id: "unknown" }, engine, dir), null);
  });
});

describe("CLI hook", () => {
  const BIN = resolve(dirname(fileURLToPath(import.meta.url)), "..", "src", "index.js");
  const env = () => ({ ...process.env, ATLAS_MCP_DATA_DIR: dir });
  const run = (sub: string, input: object) =>
    spawnSync(process.execPath, [BIN, "hook", sub], { env: env(), input: JSON.stringify(input), encoding: "utf-8" });

  it("fails closed without a config for gated tools, but not for exempt ones", () => {
    const fresh = mkdtempSync(join(tmpdir(), "atlas-mcp-hook-cli-"));
    try {
      const go = (input: object) => spawnSync(process.execPath, [BIN, "hook", "pre"], { env: { ...process.env, ATLAS_MCP_DATA_DIR: fresh }, input: JSON.stringify(input), encoding: "utf-8" });
      const gated = go(bash("ls"));
      assert.equal(gated.status, 0);
      assert.equal(JSON.parse(gated.stdout).hookSpecificOutput.permissionDecision, "deny");
      assert.equal(go({ tool_name: "Read", tool_input: { file_path: "x" } }).stdout, "");
    } finally { rmSync(fresh, { recursive: true, force: true }); }
  });

  it("init writes a config, then pre denies production end to end", () => {
    const out = execFileSync(process.execPath, [BIN, "hook", "init", "--principal", "user:alice"], { env: env(), encoding: "utf-8" });
    assert.match(out, /"PreToolUse"/);
    assert.ok(existsSync(join(dir, "hook.json")));
    assert.throws(() => execFileSync(process.execPath, [BIN, "hook", "init"], { env: env(), stdio: "pipe" }), /exists/);
    const r = run("pre", bash("kubectl get pods -n production"));
    assert.equal(JSON.parse(r.stdout).hookSpecificOutput.permissionDecision, "deny");
    assert.equal(run("pre", bash("npm test")).stdout, "");
  });
});
