# atlas-mcp

**Pre-action authorization for AI agents, as an MCP server.**

Before an agent deletes data, deploys, or spends money, it asks Atlas. Atlas checks the request against a **signed delegation chain** and answers `permit`, `deny` or `escalate`, with a receipt. After acting, the agent reports what really happened with `atlas_commit_effect`. Every step lands in a hash-chained, ML-DSA-65-signed audit log.

```
$ npx -y @corpussanctum/atlas-mcp demo

  You (alice) delegate to claude: database work in STAGING only.

  Claude: delete rows in staging
    -> PERMIT    rcpt_ec14…  authorized by 1-link delegation chain from user:alice

  Claude: delete rows in PRODUCTION
    -> DENY      rcpt_876f…  effect targets environment 'production';
                             delegated authority (grant grt_c9c8…) only permits staging

  Claude: write to staging (grant says writes need a human)
    -> ESCALATE  rcpt_a8d7…  action 'db.write' requires human approval
```

## Quickstart (5 minutes)

**1. Register the server.**

Claude Code:
```bash
claude mcp add atlas -- npx -y @corpussanctum/atlas-mcp
```

Claude Desktop (`claude_desktop_config.json`), or any MCP client:
```json
{ "mcpServers": { "atlas": { "command": "npx", "args": ["-y", "@corpussanctum/atlas-mcp"] } } }
```

Codex (`~/.codex/config.toml`):
```toml
[mcp_servers.atlas]
command = "npx"
args = ["-y", "@corpussanctum/atlas-mcp"]
```

**2. Delegate authority.** You, the principal, issue a grant to the agent:
```bash
npx -y @corpussanctum/atlas-mcp grant --principal user:alice --subject agent:claude \
  --allow 'db.*' --env staging --escalate db.write --ttl-hours 8
# prints the grant JSON; note its "id" (grt_…)
```

**3. Tell the agent the rules.** Add to `CLAUDE.md` / `AGENTS.md` (see [`examples/CLAUDE.md.snippet`](examples/CLAUDE.md.snippet)):

> Before any destructive, production, deploy or spending action, call `atlas_authorize` with agent `agent:claude`, principal `user:alice`, delegation_chain `["grt_…"]`, the action and every effect. Proceed only on `permit`. Afterwards call `atlas_commit_effect`.

**4. Approve escalations as the human.** Approval is deliberately **not** an MCP tool, so an agent cannot approve itself:
```bash
npx -y @corpussanctum/atlas-mcp resolve rcpt_a8d7… approve
npx -y @corpussanctum/atlas-mcp verify            # check the audit chain and signatures
```

## Tools

| Tool | Purpose |
|---|---|
| `atlas_authorize` | `{agent, principal, requested_action, effects[], delegation_chain[]}` → `{decision, reason, scope, receipt_id}` |
| `atlas_commit_effect` | Report what actually happened under a receipt. One commit per receipt. Effects the receipt never covered are flagged as `violation`. |
| `atlas_receipt_status` | `ready`, `pending_approval`, `rejected`, `denied`, `committed`, `expired` |
| `atlas_verify_audit` | Verify the SHA3-256 chain and every ML-DSA-65 signature |

## How decisions work

* A **grant** says: grantor → subject may do `allow` actions (minus `deny`), only in `environments`, only on `resources`, with `escalate` actions needing a human. Grants are signed by the local issuer key and recorded in the audit log.
* A **chain** runs principal → agent → sub-agent. It must be unbroken, unexpired, unrevoked, and **may only narrow** from link to link. A child grant that widens its parent is rejected.
* **Intersection semantics:** every link must independently allow the action and each effect. Revoking any link kills everything below it.
* **Fail closed:** unknown grants, bad signatures, missing environments under an environment-restricted grant, and malformed requests all deny. The server trusts its own recorded copy of a grant, never the caller's.
* Receipts expire after 15 minutes. A permit/approval covers the stated effects only.

## Read this before you rely on it

* **This is a gate the agent consults, not a sandbox.** An MCP tool cannot stop an agent that decides not to call it, or that lies about its effects. v0.1 gives you a signed, verifiable record and a decision to enforce *with*: pair it with a Claude Code `PreToolUse` hook, a tool proxy, or network/credential isolation to make it binding. `atlas_commit_effect` catches and records the mismatches it is told about.
* The issuer key sits unencrypted in `~/.atlas-mcp/issuer.json` (mode 0600). Protect the directory like an SSH key. Anyone who can read it can forge grants.
* Local operator approval = local shell access. There is no remote approval channel in v0.1.
* Not a compliance certification. Cryptographic choices follow the parent project's assumptions; no external audit has been done.

## Data and config

`ATLAS_MCP_DATA_DIR` (default `~/.atlas-mcp`) holds `issuer.json` and `audit.jsonl`. Nothing leaves the machine.

## Docker

```bash
docker build -t atlas-mcp .
docker run -i --rm -v atlas-data:/data atlas-mcp
```

## Relationship to Atlas Protocol

[`atlas-protocol`](https://github.com/corpussanctum/atlas-protocol) is the full governance gatekeeper (Telegram operator relay, 96-rule policy engine, agent identity registry, behavioral baselines, proximity). `atlas-mcp` is its smallest useful piece, extracted so you can install it in one line.

## Development

```bash
npm install && npm test
```

Apache-2.0.
