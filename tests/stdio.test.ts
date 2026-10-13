import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn, execFileSync, type ChildProcessWithoutNullStreams } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const BIN = resolve(dirname(fileURLToPath(import.meta.url)), "..", "src", "index.js");

describe("MCP stdio", () => {
  let dir: string;
  let proc: ChildProcessWithoutNullStreams;
  let buf = "";
  let nextId = 1;
  const waiters = new Map<number, (m: any) => void>();
  const stray: string[] = [];

  const rpc = (method: string, params: unknown = {}) =>
    new Promise<any>((res, rej) => {
      const id = nextId++;
      const t = setTimeout(() => rej(new Error(`timeout: ${method}`)), 8000);
      waiters.set(id, (m) => { clearTimeout(t); res(m); });
      proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    });
  const call = async (name: string, args: unknown) => {
    const r = await rpc("tools/call", { name, arguments: args });
    return { isError: r.result?.isError, error: r.error, body: r.result ? JSON.parse(r.result.content[0].text) : undefined };
  };

  before(async () => {
    dir = mkdtempSync(join(tmpdir(), "atlas-mcp-stdio-"));
    proc = spawn(process.execPath, [BIN, "serve"], { env: { ...process.env, ATLAS_MCP_DATA_DIR: dir }, stdio: ["pipe", "pipe", "pipe"] });
    proc.stderr.resume();
    proc.stdout.setEncoding("utf-8");
    proc.stdout.on("data", (c: string) => {
      buf += c;
      let i: number;
      while ((i = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, i); buf = buf.slice(i + 1);
        if (!line) continue;
        try { const m = JSON.parse(line); waiters.get(m.id)?.(m); } catch { stray.push(line); }
      }
    });
    await rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test", version: "0" } });
    proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
  });
  after(() => { proc.kill(); rmSync(dir, { recursive: true, force: true }); });

  it("lists the four tools with annotations and keeps stdout clean", async () => {
    const r = await rpc("tools/list");
    assert.deepEqual(r.result.tools.map((t: any) => t.name), ["atlas_authorize", "atlas_commit_effect", "atlas_receipt_status", "atlas_verify_audit"]);
    for (const t of r.result.tools) assert.equal(typeof t.annotations.readOnlyHint, "boolean");
    assert.deepEqual(stray, []);
  });

  it("runs the headline scenario: staging permitted, production denied, commit, verify", async () => {
    const grant = JSON.parse(execFileSync(process.execPath, [BIN, "grant", "--principal", "user:tj", "--subject", "agent:claude", "--allow", "db.*", "--env", "staging"], { env: { ...process.env, ATLAS_MCP_DATA_DIR: dir } }).toString());
    const base = { agent: "agent:claude", principal: "user:tj", requested_action: "db.delete", delegation_chain: [grant.id] };
    const e = (environment: string) => [{ type: "delete", resource: `postgres://${environment}/users`, environment }];

    const prod = await call("atlas_authorize", { ...base, effects: e("production") });
    assert.equal(prod.body.decision, "deny");

    const stg = await call("atlas_authorize", { ...base, effects: e("staging") });
    assert.equal(stg.body.decision, "permit");
    const commit = await call("atlas_commit_effect", { receipt_id: stg.body.receipt_id, outcome: "success", effects: e("staging") });
    assert.equal(commit.body.status, "recorded");
    assert.equal((await call("atlas_commit_effect", { receipt_id: stg.body.receipt_id, outcome: "success" })).isError, true);

    assert.deepEqual((await call("atlas_verify_audit", {})).body, { valid: true, entries: 4 });
  });

  it("reports bad arguments as tool errors and unknown tools as protocol errors", async () => {
    assert.equal((await call("atlas_authorize", { agent: "x" })).isError, true);
    assert.ok((await call("nope", {})).error);
  });
});
