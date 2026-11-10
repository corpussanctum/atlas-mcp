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
import { classify, isExempt, postHook, preHook, type HookConfig } from "../src/hook.js";

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
  it("exempts only Atlas's own MCP tools, not servers that share the name prefix", () => {
    assert.equal(isExempt("mcp__atlas__atlas_authorize"), true);
    assert.equal(isExempt("mcp__atlas-mcp__atlas_verify_audit"), true);
    assert.equal(isExempt("mcp__atlassian__createJiraIssue"), false);
    assert.equal(isExempt("mcp__atlas__something_else"), false);
    assert.equal(classify(cfg, "mcp__atlassian__createJiraIssue", {})?.action, "mcp.atlassian.createJiraIssue");
  });
  it("recognises environment words next to underscores, digits and punctuation", () => {
    const env = (command: string) => classify(cfg, "Bash", { command })?.effects[0].environment;
    for (const c of ["psql $PROD_DATABASE_URL -c 'select 1'", "psql -h db_prod.internal", "psql myapp_production", "kubectl --context=prod1 get pods", "psql prod-db", "deploy --env=PRD"]) {
      assert.equal(env(c), "production", c);
    }
    for (const c of ["psql $STAGING_URL", "ssh app_stg2"]) assert.equal(env(c), "staging", c);
    for (const c of ["npm run reproduce", "ls products/", "node nonprod.js", "cat upstage.txt"]) assert.equal(env(c), "dev", c);
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
  it("denies production named through an environment variable or host", () => {
    for (const c of ["psql $PROD_DATABASE_URL -c 'select 1'", "psql -h db_prod.internal"]) {
      assert.equal(pre(bash(c))?.hookSpecificOutput.permissionDecision, "deny", c);
    }
  });
  it("denies reads of Atlas's data directory, including through exempt tools", () => {
    const decision = (tool_name: string, tool_input: object, cwd?: string) => pre({ tool_name, tool_input, cwd, tool_use_id: "t" })?.hookSpecificOutput.permissionDecision;
    assert.equal(decision("Read", { file_path: join(dir, "issuer.json") }), "deny");
    assert.equal(decision("Read", { file_path: "issuer.json" }, dir), "deny");
    assert.equal(decision("Grep", { pattern: "secret", path: dir }), "deny");
    assert.equal(decision("Glob", { pattern: "/home/u/.atlas-mcp/*" }), "deny");
    // Ordinary reads stay ungated, and file content or a search regex is not a path.
    assert.equal(pre({ tool_name: "Read", tool_input: { file_path: "/srv/app/a.ts" } }), null);
    assert.equal(pre({ tool_name: "Grep", tool_input: { pattern: "\\.atlas-mcp", path: "/srv/app" } }), null);
    assert.equal(pre({ tool_name: "Write", tool_input: { file_path: "/srv/app/README.md", content: "data lives in ~/.atlas-mcp" }, tool_use_id: "w" }), null);
  });
  it("denies MCP tools whose arguments reach Atlas's data directory", () => {
    cfg.delegation_chain = [issueGrant(Issuer.loadOrCreate(dir), engine.log, { grantor: "user:alice", subject: "agent:cc", ttlHours: 1, scope: { allow: ["mcp.*"] } }).id];
    const fsWrite = (path: string) => pre({ tool_name: "mcp__filesystem__write_file", tool_input: { path, content: "" }, tool_use_id: "m" });
    const out = fsWrite(join(dir, "audit.jsonl"));
    assert.equal(out?.hookSpecificOutput.permissionDecision, "deny");
    assert.match(out!.hookSpecificOutput.permissionDecisionReason, /own authority/);
    assert.equal(pre({ tool_name: "mcp__fs__edit", tool_input: { edits: [{ target: { path: "/home/u/.atlas-mcp/hook.json" } }] }, tool_use_id: "m" })?.hookSpecificOutput.permissionDecision, "deny");
    assert.equal(fsWrite("/srv/app/a.ts"), null);
  });
  it("denies the Atlas CLI commands that change authority", () => {
    const before = engine.log.read().length;
    for (const c of [
      "atlas-mcp grant --principal user:alice --subject agent:cc --allow '*'",
      "atlas-mcp resolve rcpt_0123456789abcdef approve",
      "npx -y @corpussanctum/atlas-mcp revoke grt_000000000000",
      "npx -y @corpussanctum/atlas-mcp@0.1.1 grant --principal p --subject s --allow x",
      "cd /tmp && atlas-mcp hook init --force --env dev,staging,live",
    ]) {
      const out = pre(bash(c));
      assert.equal(out?.hookSpecificOutput.permissionDecision, "deny", c);
      assert.match(out!.hookSpecificOutput.permissionDecisionReason, /only the human operator/, c);
    }
    assert.equal(engine.log.read().length, before, "refused before reaching the engine");
    // Read-only subcommands and installing the package stay available.
    for (const c of ["atlas-mcp verify", "atlas-mcp status rcpt_0123456789abcdef", "npm i -g @corpussanctum/atlas-mcp"]) assert.equal(pre(bash(c)), null, c);
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
      const key = go({ tool_name: "Read", tool_input: { file_path: join(fresh, "issuer.json") } });
      assert.equal(JSON.parse(key.stdout).hookSpecificOutput.permissionDecision, "deny");
    } finally { rmSync(fresh, { recursive: true, force: true }); }
  });

  it("init writes a config, then pre denies production end to end", () => {
    const out = execFileSync(process.execPath, [BIN, "hook", "init", "--principal", "user:alice"], { env: env(), encoding: "utf-8" });
    assert.match(out, /"PreToolUse"/);
    assert.match(out, /"matcher": "Bash\|Read\|Grep\|Glob\|/);
    assert.equal(JSON.parse(run("pre", { tool_name: "Read", tool_input: { file_path: join(dir, "issuer.json") } }).stdout).hookSpecificOutput.permissionDecision, "deny");
    assert.ok(existsSync(join(dir, "hook.json")));
    assert.throws(() => execFileSync(process.execPath, [BIN, "hook", "init"], { env: env(), stdio: "pipe" }), /exists/);
    const r = run("pre", bash("kubectl get pods -n production"));
    assert.equal(JSON.parse(r.stdout).hookSpecificOutput.permissionDecision, "deny");
    assert.equal(run("pre", bash("npm test")).stdout, "");
  });
});
