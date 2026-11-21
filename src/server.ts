import { ProtocolError, ProtocolErrorCode, Server, type JsonSchemaType, type Tool } from "@modelcontextprotocol/server";
import { StdioServerTransport } from "@modelcontextprotocol/server/stdio";
import { AjvJsonSchemaValidator } from "@modelcontextprotocol/server/validators/ajv";
import { Engine, type AuthorizeRequest, type Effect } from "./engine.js";
import type { EffectAttestation } from "./effects/contract.js";
import { VERSION } from "./version.js";

const effectSchema: Record<string, any> = {
  type: "object",
  properties: {
    type: { type: "string", description: "read | write | create | delete | exec | send | spend (free-form)" },
    resource: { type: "string", description: "What is touched, e.g. postgres://prod/users" },
    environment: { type: "string", description: "e.g. staging or production" },
    irreversible: { type: "boolean" },
  },
  required: ["type", "resource"],
};

const contractSchema: Record<string, any> = {
  type: "object",
  properties: {
    mode: { type: "string", enum: ["declared", "observed"] },
    observer: { type: "string", description: "Id of the enforcement point that derives effects from the operation" },
    operation_hash: { type: "string", description: "SHA3-256 of the canonical operation bound to this receipt" },
  },
  required: ["mode"],
};

const attestationSchema: Record<string, any> = {
  type: "object",
  properties: {
    observer: { type: "string" },
    operation_hash: { type: "string" },
    effects: { type: "array", items: effectSchema, description: "Effects independently observed by the enforcement point" },
    observed_at: { type: "string" },
    signature: { type: "string", description: "Optional ML-DSA-65 signature over the canonical attestation payload" },
  },
  required: ["observer", "operation_hash", "effects"],
};

export const toolDefinitions: Tool[] = [
  {
    name: "atlas_authorize",
    title: "Authorize Action",
    description:
      "Ask for authorization BEFORE doing anything consequential (deleting data, deploying, spending, sending). " +
      "Atlas checks the action and its effects against the signed delegation chain and returns permit, deny or escalate with a receipt_id. " +
      "Do not perform the action unless the decision is permit (or escalate that a human later approved).",
    inputSchema: {
      type: "object",
      properties: {
        agent: { type: "string", description: "Your agent id, as named in the last delegation grant" },
        principal: { type: "string", description: "The human or system that originally delegated authority" },
        requested_action: { type: "string", description: "Action name, e.g. db.delete" },
        effects: { type: "array", items: effectSchema, description: "Every effect the action will have. Be complete and honest." },
        delegation_chain: {
          type: "array",
          items: { type: "string" },
          description: "Grant ids, root first (principal -> ... -> you)",
        },
        enforcement: { ...contractSchema, description: "Optional F1 enforcement contract. Use mode 'observed' to bind the receipt to an operation and require an observer attestation at commit." },
      },
      required: ["agent", "principal", "requested_action", "effects", "delegation_chain"],
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  },
  {
    name: "atlas_commit_effect",
    title: "Report Completed Effects",
    description:
      "After acting on a permitted receipt, report what was actually done. Atlas records it in the signed audit log and flags any effect the receipt did not cover. One commit per receipt. " +
      "Set late to true when the action already ran and the receipt expired or its grant was revoked while it was running; the outcome is still recorded and revoked authority is flagged as a violation.",
    inputSchema: {
      type: "object",
      properties: {
        receipt_id: { type: "string" },
        outcome: { type: "string", enum: ["success", "failure"] },
        effects: { type: "array", items: effectSchema, description: "Caller-reported effects (legacy declared mode only)" },
        note: { type: "string" },
        late: { type: "boolean", description: "Report an action that already ran after expiry or revocation" },
        attestation: { ...attestationSchema, description: "Required for observed receipts; must come from the enforcement point, not the agent" },
      },
      required: ["receipt_id", "outcome"],
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  },
  {
    name: "atlas_receipt_status",
    title: "Check Receipt Status",
    description:
      "Check a receipt: ready, pending_approval (escalated, waiting for a human), rejected, denied, committed, expired, or revoked (a grant behind it was revoked). " +
      "Approval can only be given by a human through the atlas-mcp CLI, never through this server.",
    inputSchema: { type: "object", properties: { receipt_id: { type: "string" } }, required: ["receipt_id"] },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  {
    name: "atlas_pending_permits",
    title: "List Uncommitted Permits",
    description:
      "List permitted receipts that have no commit yet. A permit with no commit can mean the action ran outside Atlas, so this is an alerting surface for operators and monitoring, not an agent tool. " +
      "Use older_than_ms to separate in-flight calls from stale permits.",
    inputSchema: {
      type: "object",
      properties: { older_than_ms: { type: "integer", minimum: 0, description: "Only mark permits older than this as alerts" } },
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  {
    name: "atlas_verify_audit",
    title: "Verify Audit Log",
    description: "Verify the audit log's SHA3-256 hash chain and ML-DSA-65 signatures. Reports the first broken entry, if any.",
    inputSchema: { type: "object", properties: {} },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
];

type Args = Record<string, unknown>;
const text = (v: unknown, isError = false) => ({ content: [{ type: "text" as const, text: JSON.stringify(v, null, 2) }], ...(isError ? { isError: true } : {}) });

export function createHandlers(engine: Engine): Record<string, (a: Args) => unknown> {
  return {
    atlas_authorize: (a) => text(engine.authorize(a as unknown as AuthorizeRequest)),
    atlas_commit_effect: (a) => {
      try {
        return text(engine.commit({
          receipt_id: a.receipt_id as string,
          outcome: a.outcome as "success" | "failure",
          effects: a.effects as Effect[] | undefined,
          note: a.note as string | undefined,
          late: a.late as boolean | undefined,
          attestation: a.attestation as EffectAttestation | undefined,
        }));
      } catch (err) {
        return text({ error: (err as Error).message }, true);
      }
    },
    atlas_receipt_status: (a) => text(engine.status(a.receipt_id as string)),
    atlas_pending_permits: (a) => text(engine.pendingPermits(new Date(), Number(a.older_than_ms ?? 0))),
    atlas_verify_audit: () => text(engine.log.verify()),
  };
}

export async function serve(engine: Engine): Promise<void> {
  const mcp = new Server(
    { name: "atlas-mcp", version: VERSION },
    {
      capabilities: { tools: {} },
      instructions:
        "Atlas is a pre-action authorization gate. Before any consequential action, call atlas_authorize with the action, " +
        "its effects and your delegation chain; proceed only on permit. Afterwards call atlas_commit_effect with what actually happened. " +
        "When enforcement.mode is observed, effects must be derived by the trusted enforcement point and committed with its signed attestation; " +
        "caller-reported effects alone cannot satisfy an observed receipt.",
    },
  );
  const handlers = createHandlers(engine);
  const validator = new AjvJsonSchemaValidator();
  const validators = new Map(toolDefinitions.map((d) => [d.name, validator.getValidator(d.inputSchema as JsonSchemaType)]));

  mcp.setRequestHandler("tools/list", async () => ({ tools: toolDefinitions }));
  mcp.setRequestHandler("tools/call", async (request) => {
    const { name, arguments: args } = request.params;
    const handler = Object.hasOwn(handlers, name) ? handlers[name] : undefined;
    const validate = validators.get(name);
    if (!handler || !validate) throw new ProtocolError(ProtocolErrorCode.InvalidParams, `Unknown tool: ${name}`);
    const checked = validate(args ?? {});
    if (!checked.valid) return text({ error: `Invalid arguments for ${name}: ${checked.errorMessage}` }, true);
    return handler((args ?? {}) as Args) as never;
  });
  await mcp.connect(new StdioServerTransport());
}
