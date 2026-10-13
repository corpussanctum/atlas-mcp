import { ProtocolError, ProtocolErrorCode, Server, type JsonSchemaType, type Tool } from "@modelcontextprotocol/server";
import { StdioServerTransport } from "@modelcontextprotocol/server/stdio";
import { AjvJsonSchemaValidator } from "@modelcontextprotocol/server/validators/ajv";
import { Engine, type AuthorizeRequest, type Effect } from "./engine.js";
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

export const toolDefinitions: Tool[] = [
  {
    name: "atlas_authorize",
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
      },
      required: ["agent", "principal", "requested_action", "effects", "delegation_chain"],
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  },
  {
    name: "atlas_commit_effect",
    description:
      "After acting on a permitted receipt, report what was actually done. Atlas records it in the signed audit log and flags any effect the receipt did not cover. One commit per receipt.",
    inputSchema: {
      type: "object",
      properties: {
        receipt_id: { type: "string" },
        outcome: { type: "string", enum: ["success", "failure"] },
        effects: { type: "array", items: effectSchema, description: "Effects that actually happened" },
        note: { type: "string" },
      },
      required: ["receipt_id", "outcome"],
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  },
  {
    name: "atlas_receipt_status",
    description:
      "Check a receipt: ready, pending_approval (escalated, waiting for a human), rejected, denied, committed or expired. " +
      "Approval can only be given by a human through the atlas-mcp CLI, never through this server.",
    inputSchema: { type: "object", properties: { receipt_id: { type: "string" } }, required: ["receipt_id"] },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  {
    name: "atlas_verify_audit",
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
        return text(engine.commit({ receipt_id: a.receipt_id as string, outcome: a.outcome as "success" | "failure", effects: a.effects as Effect[] | undefined, note: a.note as string | undefined }));
      } catch (err) {
        return text({ error: (err as Error).message }, true);
      }
    },
    atlas_receipt_status: (a) => text(engine.status(a.receipt_id as string)),
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
        "its effects and your delegation chain; proceed only on permit. Afterwards call atlas_commit_effect with what actually happened.",
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
