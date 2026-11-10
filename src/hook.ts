import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { Engine, type Effect } from "./engine.js";

/**
 * Claude Code hook adapter. `hook pre` maps a tool call to an Atlas action plus
 * effects, asks the engine, and answers deny / ask / defer. `hook post` closes
 * the loop with atlas_commit_effect semantics.
 *
 * What this is: a policy check that runs OUTSIDE the model, so the agent cannot
 * skip it. What it is not: a sandbox. Classification is pattern-based, so a
 * command the patterns do not recognise is treated as ordinary `shell.exec`.
 */

export interface HookConfig {
  agent: string;
  principal: string;
  delegation_chain: string[];
  /** Environment assumed when no pattern matches. Unset: effects carry no environment. */
  default_environment?: string;
  /** First matching pattern (tested against the resource string) names the environment. */
  environments?: Array<{ match: string; environment: string }>;
  /** Extra rules, checked before the built-ins. */
  rules?: HookRule[];
  /** On `permit`, answer "allow" (skip Claude Code's own prompt) or defer to it. Default "defer". */
  on_permit?: "defer" | "allow";
}

export interface HookRule {
  tool: string; // regex against tool_name
  match?: string; // regex against the resource (command, path, url)
  action: string;
  effect_type: string;
  irreversible?: boolean;
}

export interface HookInput {
  hook_event_name?: string;
  tool_name?: string;
  tool_input?: Record<string, unknown>;
  tool_use_id?: string;
  session_id?: string;
  cwd?: string;
  tool_response?: unknown;
}

export interface HookOutput {
  hookSpecificOutput: {
    hookEventName: "PreToolUse";
    permissionDecision: "allow" | "deny" | "ask";
    permissionDecisionReason: string;
  };
}

export const DEFAULT_ENVIRONMENTS = [
  // Letter boundaries, not \b: `_` and digits are word characters, so \b misses PROD_DB_URL, db_prod, prod1.
  { match: "(?<![a-z])(prod|production|prd)(?![a-z])", environment: "production" },
  { match: "(?<![a-z])(stage|staging|stg)(?![a-z])", environment: "staging" },
];

const BUILTIN: HookRule[] = [
  { tool: "^Bash$", match: "\\b(terraform\\s+(apply|destroy)|kubectl\\s+(apply|delete|rollout|scale)|helm\\s+(install|upgrade|uninstall)|git\\s+push(?!.*--force)|npm\\s+publish|docker\\s+push|vercel\\s+(deploy|--prod)|wrangler\\s+(publish|deploy))\\b", action: "shell.deploy", effect_type: "deploy" },
  { tool: "^Bash$", match: "(\\brm\\s+-[a-zA-Z]*[rf]|\\brmdir\\b|\\bshred\\b|\\btruncate\\b|\\bmkfs|\\bdd\\s+if=|\\bdrop\\s+(table|database|schema)\\b|\\bdelete\\s+from\\b|git\\s+reset\\s+--hard|git\\s+clean\\s+-[a-z]*f|git\\s+push\\b.*--force)", action: "shell.delete", effect_type: "delete", irreversible: true },
  { tool: "^Bash$", action: "shell.exec", effect_type: "exec" },
  { tool: "^(Write|Edit|MultiEdit|NotebookEdit)$", action: "file.write", effect_type: "write" },
  { tool: "^(WebFetch|WebSearch)$", action: "network.fetch", effect_type: "read" },
];

/**
 * Tools Atlas does not gate: reads, planning, and Atlas's own MCP tools. The
 * server and tool names are matched exactly: a prefix test would also exempt
 * unrelated servers such as `mcp__atlassian__*`.
 */
export function isExempt(tool: string): boolean {
  return /^(Read|Glob|Grep|LS|TodoWrite|ExitPlanMode|Task|BashOutput|KillShell)$/.test(tool)
    || /^mcp__atlas(-mcp)?__atlas_(authorize|commit_effect|receipt_status|verify_audit)$/.test(tool);
}

/** The Atlas CLI subcommands that change authority; only the human operator may run them. */
const AUTHORITY_CLI = /atlas-mcp(?:@[\w.-]+)?["']?\s+(grant|revoke|resolve|hook\s+init)\b/i;

/** Inputs that hold a filesystem path, per tool. Other inputs (file content, search regexes) are not paths. */
const PATH_FIELDS: Record<string, string[]> = {
  Read: ["file_path"], Write: ["file_path"], Edit: ["file_path"], MultiEdit: ["file_path"], NotebookEdit: ["notebook_path"],
  Glob: ["path", "pattern"], Grep: ["path", "glob"], LS: ["path"],
};

function strings(v: unknown, out: string[] = []): string[] {
  if (typeof v === "string") out.push(v);
  else if (Array.isArray(v)) for (const x of v) strings(x, out);
  else if (v && typeof v === "object") for (const x of Object.values(v)) strings(x, out);
  return out;
}

/**
 * Why a tool call would touch Atlas's own authority, or undefined. Runs for
 * every tool, exempt or not: reading the issuer key is as bad as editing a
 * grant. Tools with known path inputs are checked on those; a shell command is
 * checked whole; anything else (MCP tools) on every string it is given.
 */
export function selfProtection(input: HookInput, dataDir: string): string | undefined {
  const tool = input.tool_name ?? "";
  const args = input.tool_input ?? {};
  const protectedDir = resolve(dataDir);
  const fields = PATH_FIELDS[tool];
  const values = fields ? fields.map((k) => args[k]).filter((v): v is string => typeof v === "string") : strings(args);
  const candidates = fields ? values.flatMap((v) => [v, resolve(input.cwd ?? process.cwd(), v)]) : values;
  if (candidates.some((v) => v.includes(protectedDir) || /\.atlas-mcp\b/.test(v))) {
    return `'${tool}' touches Atlas's own data directory; agents cannot read or change their own authority.`;
  }
  const command = tool === "Bash" && typeof args.command === "string" ? args.command : "";
  const cli = AUTHORITY_CLI.exec(command);
  if (cli) return `'atlas-mcp ${cli[1].replace(/\s+/g, " ")}' changes delegated authority; only the human operator may run it, in their own shell.`;
  return undefined;
}

function resourceOf(tool: string, input: Record<string, unknown> = {}): string {
  const s = (k: string) => (typeof input[k] === "string" ? (input[k] as string) : undefined);
  return s("command") ?? s("file_path") ?? s("notebook_path") ?? s("url") ?? s("query") ?? JSON.stringify(input).slice(0, 500);
}

export function classify(
  cfg: HookConfig,
  tool: string,
  input: Record<string, unknown> | undefined,
): { action: string; effects: Effect[] } | null {
  if (isExempt(tool)) return null;
  const resource = resourceOf(tool, input);

  let rule: HookRule | undefined;
  const mcp = /^mcp__(.+?)__(.+)$/.exec(tool);
  for (const r of [...(cfg.rules ?? []), ...BUILTIN]) {
    if (new RegExp(r.tool).test(tool) && (!r.match || new RegExp(r.match, "i").test(resource))) { rule = r; break; }
  }
  if (!rule && mcp) rule = { tool, action: `mcp.${mcp[1]}.${mcp[2]}`, effect_type: "call" };
  if (!rule) return null; // unrecognised tool: leave to Claude Code's own permissions

  const environment = inferEnvironment(cfg, resource);
  const effect: Effect = { type: rule.effect_type, resource: mcp && !rule.match ? `mcp://${mcp[1]}/${mcp[2]}` : resource, ...(environment ? { environment } : {}), ...(rule.irreversible ? { irreversible: true } : {}) };
  return { action: rule.action, effects: [effect] };
}

function inferEnvironment(cfg: HookConfig, resource: string): string | undefined {
  for (const e of cfg.environments ?? DEFAULT_ENVIRONMENTS) if (new RegExp(e.match, "i").test(resource)) return e.environment;
  return cfg.default_environment;
}

export function loadHookConfig(dataDir: string): HookConfig {
  const path = process.env.ATLAS_MCP_HOOK_CONFIG ?? join(dataDir, "hook.json");
  if (!existsSync(path)) throw new Error(`no hook config at ${path}; run: atlas-mcp hook init`);
  const cfg = JSON.parse(readFileSync(path, "utf-8")) as HookConfig;
  if (!cfg.agent || !cfg.principal || !Array.isArray(cfg.delegation_chain)) throw new Error(`${path}: needs agent, principal and delegation_chain`);
  return cfg;
}

const deny = (reason: string): HookOutput => ({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: reason } });

/** Returns null to defer to Claude Code's normal permission flow. */
export function preHook(input: HookInput, engine: Engine, cfg: HookConfig, dataDir: string): HookOutput | null {
  // The agent must not read or edit its own authority. Checked before classification so it also covers exempt tools.
  const self = selfProtection(input, dataDir);
  if (self) return deny(`Atlas: ${self}`);

  const tool = input.tool_name ?? "";
  const call = classify(cfg, tool, input.tool_input);
  if (!call) return null;

  const r = engine.authorize({ agent: cfg.agent, principal: cfg.principal, requested_action: call.action, effects: call.effects, delegation_chain: cfg.delegation_chain });
  // A denied call never runs, so nothing will come back to collect a marker for it.
  if (input.tool_use_id && r.decision !== "deny") savePending(dataDir, input.tool_use_id, r.receipt_id);

  const tag = `Atlas ${r.decision} [${r.receipt_id}]: ${r.reason}`;
  if (r.decision === "deny") return deny(tag);
  if (r.decision === "escalate") return { hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "ask", permissionDecisionReason: tag } };
  if (cfg.on_permit === "allow") return { hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "allow", permissionDecisionReason: tag } };
  return null;
}

/**
 * Close the loop after the tool ran. If the call had been escalated and ran, a
 * human accepted Claude Code's prompt, so record that approval first. The
 * effects committed are the ones classified before the call, not independently
 * observed: the hook cannot see what a shell command really did.
 */
export function postHook(input: HookInput, engine: Engine, dataDir: string): string | null {
  const id = input.tool_use_id;
  const receipt = id ? takePending(dataDir, id) : undefined;
  if (!receipt) return null;
  const st = engine.status(receipt);
  if (st.state === "pending_approval") engine.resolve(receipt, "approve", "claude-code-prompt", `tool ${input.tool_name} ran after the user accepted the permission prompt`);
  const failed = input.hook_event_name === "PostToolUseFailure" || isErrorResponse(input.tool_response);
  const authorized = (engine.log.read().find((e) => e.type === "AUTHORIZE" && `rcpt_${e.hash.slice(0, 16)}` === receipt)?.data.effects ?? []) as Effect[];
  // late: the tool has already run, so record it even if the receipt expired or its grant was revoked meanwhile.
  engine.commit({ receipt_id: receipt, outcome: failed ? "failure" : "success", effects: authorized, late: true, note: "recorded by PostToolUse hook; effects as classified, not independently observed" });
  return receipt;
}

function isErrorResponse(r: unknown): boolean {
  return typeof r === "object" && r !== null && ((r as Record<string, unknown>).is_error === true || (r as Record<string, unknown>).success === false);
}

const safeId = (id: string) => id.replace(/[^A-Za-z0-9_-]/g, "_");
function pendingPath(dataDir: string, id: string): string {
  const dir = join(dataDir, "hook-pending");
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  return join(dir, `${safeId(id)}.json`);
}
/** Markers older than this belong to calls that never reported back (a prompt the user declined, a killed session). */
export const PENDING_MAX_AGE_MS = 24 * 3_600_000;

function savePending(dataDir: string, id: string, receipt: string): void {
  const path = pendingPath(dataDir, id);
  writeFileSync(path, JSON.stringify({ receipt_id: receipt }), { mode: 0o600 });
  sweepPending(join(dataDir, "hook-pending"));
}
export function sweepPending(dir: string, now = Date.now()): void {
  try {
    for (const f of readdirSync(dir)) {
      const p = join(dir, f);
      try { if (now - statSync(p).mtimeMs > PENDING_MAX_AGE_MS) unlinkSync(p); } catch { /* raced with another hook */ }
    }
  } catch { /* nothing to sweep */ }
}
function takePending(dataDir: string, id: string): string | undefined {
  const p = pendingPath(dataDir, id);
  if (!existsSync(p)) return undefined;
  const receipt = (JSON.parse(readFileSync(p, "utf-8")) as { receipt_id: string }).receipt_id;
  unlinkSync(p);
  return receipt;
}
