# Privacy Policy

_Last updated: 2026-10-13_

Atlas MCP (`@corpussanctum/atlas-mcp`) is a local-first tool. It runs on your machine and sends nothing anywhere.

## Data we collect

None. The Atlas MCP maintainers (Corpus Sanctum) do not receive, collect, or have access to any data from your use of the software. The code makes no network calls and contains no telemetry, analytics, crash reporting, or update checks.

## Data stored on your machine

Atlas stores its state locally, in `~/.atlas-mcp` by default (override with `ATLAS_MCP_DATA_DIR`). The directory is created with mode `0700` (owner access only). It holds:

- your signing keys,
- delegation grants,
- authorization receipts,
- the signed, hash-chained audit log, which records the actions, effects, agent and principal identifiers that you or your agent submit.

This data stays on your disk. You control it and can inspect or delete it at any time. Deleting the audit log removes the tamper-evidence it provided.

## Sharing

Atlas does not share data with us or any third party. The MCP server communicates only with the MCP client that launched it, over local stdio. Your MCP client (for example Claude Code) and the AI model behind it have their own privacy practices, which are separate from Atlas; the content of Atlas tool calls and results passes through them.

## Retention

Atlas retains data until you delete it. We hold nothing, so there is nothing for us to retain or delete on your behalf.

## Children

Atlas is a developer tool and is not directed at children.

## Changes

Changes to this policy will be published in this file, with the date above updated.

## Contact

Questions: open an issue at https://github.com/corpussanctum/atlas-mcp/issues
