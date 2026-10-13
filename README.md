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

## Enforce it: the Claude Code hook

The MCP tools are a gate the agent *chooses* to call. The hook makes the check unskippable for Claude Code: it runs outside the model on every gated tool call, so the agent cannot forget, or talk its way past, a `deny`.

```bash
npm i -g @corpussanctum/atlas-mcp       # a global install avoids npx startup cost on every tool call
atlas-mcp hook init --principal user:alice
```

`hook init` writes `~/.atlas-mcp/hook.json`, issues a starter grant (30 days; environments `dev` and `staging`; `shell.deploy` and `shell.delete` ask first), and prints the `settings.json` block to paste into `~/.claude/settings.json`.

### What happens on each tool call

| Claude Code tool call | Atlas action | Result |
|---|---|---|
| `npm test` in dev | `shell.exec` | no opinion: Claude Code's normal permissions apply |
| `psql … production` | `shell.exec` @ production | **deny**: the delegated authority only permits dev, staging |
| `rm -rf dist`, `git push --force`, `drop table` | `shell.delete` | **ask**: Claude Code prompts you; acceptance is recorded as the approval |
| `kubectl apply`, `terraform apply`, `npm publish` | `shell.deploy` | **ask** |
| `Write` / `Edit` / `MultiEdit` | `file.write` | by grant |
| `mcp__server__tool` | `mcp.server.tool` | by grant |
| `Read`, `Grep`, `Glob`, Atlas's own tools | not gated | |

The `PostToolUse` hook then commits the receipt (success or failure) to the signed audit log. Check it any time with `atlas-mcp verify`.

### Tuning

Edit `~/.atlas-mcp/hook.json`:

```json
{
  "agent": "agent:claude-code",
  "principal": "user:alice",
  "delegation_chain": ["grt_…"],
  "default_environment": "dev",
  "environments": [{ "match": "\\b(prod|production|live)\\b", "environment": "production" }],
  "rules": [{ "tool": "^Bash$", "match": "^make release", "action": "shell.deploy", "effect_type": "deploy" }],
  "on_permit": "defer"
}
```

`on_permit: "allow"` lets an Atlas permit skip Claude Code's own prompt. The default, `defer`, keeps Claude Code's prompts as a second layer.

### What it does not do (read this)

* **Classification is pattern matching.** A command Atlas doesn't recognise is plain `shell.exec`, and environment is inferred from words in the command (`prod`, `production`, `staging`). `./deploy.sh` or a connection string with no environment word passes as `dev`. Add `rules` and `environments` for your own tooling. This is a speed bump against mistakes and a record for audit, not a defence against an agent actively hiding its intent.
* **Effects are as classified, not observed.** The audit log records what Atlas judged the call would do, not what the process really did.
* **Hook failures.** The hook answers `deny` when it can catch its own error (missing config, bad grant). A hard crash or timeout is not blocked by Claude Code unless your build supports `"onFailure": "block"` on the hook handler (documented for recent versions); add it to both hook entries if yours does.
* **Permission modes.** Claude Code's docs don't say whether a hook `deny` survives `--permission-mode bypassPermissions`. We tested it on Claude Code 2.1.296 (Claude Code): a denied command did not run under `bypassPermissions` (the control command ran and was committed). Retest after upgrading Claude Code.
* **Self-protection is partial.** Edits to `~/.atlas-mcp` and commands that name it are refused, but a shell can reach a file by many routes. Run agents as a different OS user from the one that owns the data directory if that matters to you.
* Claude Code only. Other clients need their own enforcement point.

## Read this before you rely on it

* **This is a gate the agent consults, not a sandbox.** On its own, an MCP tool cannot stop an agent that decides not to call it, or that lies about its effects. v0.1 gives you a signed, verifiable record and a decision to enforce *with*: for Claude Code, use the hook above to make it binding; elsewhere pair it with a tool proxy or network/credential isolation. `atlas_commit_effect` catches and records the mismatches it is told about.
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
