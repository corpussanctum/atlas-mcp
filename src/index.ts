#!/usr/bin/env node
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { AuditLog } from "./audit.js";
import { Engine } from "./engine.js";
import { issueGrant, revokeGrant, type Scope } from "./grants.js";
import { Issuer } from "./keys.js";
import { serve } from "./server.js";
import { isExempt, loadHookConfig, postHook, preHook, type HookConfig, type HookInput } from "./hook.js";
import { VERSION } from "./version.js";

const HELP = `atlas-mcp ${VERSION}: pre-action authorization for AI agents

  atlas-mcp [serve]                 run the MCP server on stdio (default)
  atlas-mcp grant --principal P --subject S --allow a,b [--deny ..] [--escalate ..]
                  [--env staging,dev] [--resources 'postgres://staging/*'] [--ttl-hours 8]
                                    issue a signed delegation grant; prints its JSON
  atlas-mcp revoke <grant_id> [--reason ..]
  atlas-mcp resolve <receipt_id> approve|reject [--by NAME] [--note ..]
                                    human decision on an escalated receipt
  atlas-mcp status <receipt_id>
  atlas-mcp verify                  verify the audit hash chain and signatures
  atlas-mcp hook init [--principal P] [--env dev,staging]
                                    set up the Claude Code hook (config + grant); prints settings.json
  atlas-mcp hook pre|post           hook entry points (read the Claude Code event on stdin)
  atlas-mcp demo                    two-minute scripted demo (uses a throwaway data dir)

Data dir: $ATLAS_MCP_DATA_DIR (default ~/.atlas-mcp)
`;

const list = (s?: string) => (s ? s.split(",").map((x) => x.trim()).filter(Boolean) : undefined);

function open(dataDir: string) {
  const issuer = Issuer.loadOrCreate(dataDir);
  const log = new AuditLog(dataDir, issuer);
  return { issuer, log, engine: new Engine(issuer, log) };
}

async function main(): Promise<number> {
  const dataDir = process.env.ATLAS_MCP_DATA_DIR ?? join(homedir(), ".atlas-mcp");
  const [cmd = "serve", ...rest] = process.argv.slice(2);
  const opts = {
    principal: { type: "string" }, subject: { type: "string" }, allow: { type: "string" }, deny: { type: "string" },
    escalate: { type: "string" }, env: { type: "string" }, resources: { type: "string" }, "ttl-hours": { type: "string" },
    reason: { type: "string" }, by: { type: "string" }, note: { type: "string" }, force: { type: "boolean" },
  } as const;
  const { values, positionals } = parseArgs({ args: rest, options: opts, allowPositionals: true });

  switch (cmd) {
    case "serve": {
      await serve(open(dataDir).engine);
      return -1; // keep running
    }
    case "grant": {
      if (!values.principal || !values.subject || !values.allow) throw new Error("grant needs --principal, --subject and --allow");
      const { issuer, log } = open(dataDir);
      const scope: Scope = { allow: list(values.allow)!, deny: list(values.deny), escalate: list(values.escalate), environments: list(values.env), resources: list(values.resources) };
      console.log(JSON.stringify(issueGrant(issuer, log, { grantor: values.principal, subject: values.subject, scope, ttlHours: Number(values["ttl-hours"] ?? 8) }), null, 2));
      return 0;
    }
    case "revoke":
      revokeGrant(open(dataDir).log, positionals[0], values.reason ?? "revoked by operator");
      console.log(`revoked ${positionals[0]}`);
      return 0;
    case "resolve": {
      const [receipt, outcome] = positionals;
      if (outcome !== "approve" && outcome !== "reject") throw new Error("usage: resolve <receipt_id> approve|reject");
      open(dataDir).engine.resolve(receipt, outcome, values.by ?? process.env.USER ?? "operator", values.note);
      console.log(`${outcome}d ${receipt}`);
      return 0;
    }
    case "status":
      console.log(JSON.stringify(open(dataDir).engine.status(positionals[0]), null, 2));
      return 0;
    case "verify": {
      const r = open(dataDir).log.verify();
      console.log(JSON.stringify(r, null, 2));
      return r.valid ? 0 : 1;
    }
    case "hook":
      return hook(dataDir, positionals[0], values);
    case "demo":
      return demo();
    case "-h": case "--help": case "help":
      console.log(HELP);
      return 0;
    default:
      console.error(HELP);
      return 2;
  }
}

/**
 * Claude Code hook entry points. Exit 0 always; the decision travels in the JSON.
 * A crash must never fail open for a gated tool, so `pre` answers deny on error.
 */
function hook(dataDir: string, sub: string | undefined, values: Record<string, string | boolean | undefined>): number {
  if (sub === "init") return hookInit(dataDir, values);
  if (sub !== "pre" && sub !== "post") throw new Error("usage: hook init|pre|post");

  let input: HookInput = {};
  try {
    input = JSON.parse(readFileSync(0, "utf-8") || "{}") as HookInput;
    const { engine } = open(dataDir);
    if (sub === "pre") {
      const out = preHook(input, engine, loadHookConfig(dataDir), dataDir);
      if (out) console.log(JSON.stringify(out));
    } else {
      postHook(input, engine, dataDir);
    }
  } catch (err) {
    const msg = `Atlas hook error: ${(err as Error).message}`;
    console.error(msg);
    if (sub === "pre" && !isExempt(input.tool_name ?? "")) {
      console.log(JSON.stringify({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: `${msg} (failing closed)` } }));
    }
  }
  return 0;
}

function hookInit(dataDir: string, values: Record<string, string | boolean | undefined>): number {
  const cfgPath = join(dataDir, "hook.json");
  if (existsSync(cfgPath) && !values.force) throw new Error(`${cfgPath} exists; pass --force to replace it`);
  const { issuer, log } = open(dataDir);
  const principal = (values.principal as string | undefined) ?? `user:${process.env.USER ?? "operator"}`;
  const agent = (values.subject as string | undefined) ?? "agent:claude-code";
  const envs = list(values.env as string | undefined) ?? ["dev", "staging"];
  const g = issueGrant(issuer, log, {
    grantor: principal, subject: agent, ttlHours: Number(values["ttl-hours"] ?? 24 * 30),
    scope: { allow: ["file.write", "shell.exec", "shell.deploy", "shell.delete", "network.fetch", "mcp.*"], escalate: ["shell.deploy", "shell.delete"], environments: envs },
  });
  const cfg: HookConfig = { agent, principal, delegation_chain: [g.id], default_environment: "dev" };
  writeFileSync(cfgPath, JSON.stringify(cfg, null, 2) + "\n", { mode: 0o600 });
  console.log(`Wrote ${cfgPath} and grant ${g.id} (environments: ${envs.join(", ")}; deploy/delete ask first).\n`);
  console.log("Add to ~/.claude/settings.json (or .claude/settings.json):\n");
  console.log(JSON.stringify({
    hooks: {
      PreToolUse: [{ matcher: "Bash|Write|Edit|MultiEdit|NotebookEdit|WebFetch|mcp__.*", hooks: [{ type: "command", command: "atlas-mcp hook pre", timeout: 30 }] }],
      PostToolUse: [{ matcher: "Bash|Write|Edit|MultiEdit|NotebookEdit|WebFetch|mcp__.*", hooks: [{ type: "command", command: "atlas-mcp hook post", timeout: 30 }] }],
    },
  }, null, 2));
  return 0;
}

function demo(): number {
  const dir = mkdtempSync(join(tmpdir(), "atlas-mcp-demo-"));
  try {
    const { issuer, log, engine } = open(dir);
    const say = (s: string) => console.log(s);
    say("\n  You (alice) delegate to claude: database work in STAGING only; deletes need no one else.\n");
    const g = issueGrant(issuer, log, {
      grantor: "user:alice", subject: "agent:claude",
      scope: { allow: ["db.read", "db.write", "db.delete"], environments: ["staging"], escalate: ["db.write"] }, ttlHours: 8,
    });
    say(`  grant ${g.id}: allow db.read/db.write/db.delete @ staging, db.write needs approval\n`);

    const ask = (label: string, action: string, environment: string) => {
      const r = engine.authorize({
        agent: "agent:claude", principal: "user:alice", requested_action: action,
        effects: [{ type: action.split(".")[1], resource: `postgres://${environment}/users`, environment, irreversible: action === "db.delete" }],
        delegation_chain: [g.id],
      });
      say(`  ${label}\n    -> ${r.decision.toUpperCase()}  ${r.receipt_id}\n       ${r.reason}\n`);
      return r;
    };
    const ok = ask("Claude: delete rows in staging", "db.delete", "staging");
    engine.commit({ receipt_id: ok.receipt_id, outcome: "success", effects: [{ type: "delete", resource: "postgres://staging/users", environment: "staging" }] });
    ask("Claude: delete rows in PRODUCTION", "db.delete", "production");
    const esc = ask("Claude: write to staging", "db.write", "staging");
    say(`  human approves:  atlas-mcp resolve ${esc.receipt_id} approve\n`);
    engine.resolve(esc.receipt_id, "approve", "alice");
    say(`  receipt state now: ${engine.status(esc.receipt_id).state}\n`);
    say(`  audit log: ${JSON.stringify(log.verify())}\n`);
    return 0;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

main().then(
  (code) => { if (code >= 0) process.exit(code); },
  (err) => { console.error(`atlas-mcp: ${(err as Error).message}`); process.exit(1); },
);
