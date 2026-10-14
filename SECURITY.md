# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** through GitHub: the repository's **Security** tab > **Report a vulnerability** (private vulnerability reporting), or by email to tj@corpussanctum.ai. Please do not open a public issue for security problems.

Include what you found, the affected version, and steps to reproduce. We aim to acknowledge reports within 5 business days and will keep you updated on the fix and disclosure timing. This is a small project maintained on a best-effort basis.

## Supported versions

Only the latest published release of `@corpussanctum/atlas-mcp` receives security fixes.

## Scope

In scope: the authorization engine, delegation-chain and grant verification, receipt and audit-log signing and verification, the CLI, and the Claude Code hook.

## Known and documented limitations

These are disclosed design limits, not vulnerabilities:

- The issuer private key is stored unencrypted at `~/.atlas-mcp/issuer.json` (mode `0600`, not hardware- or OS-keychain-backed). Anyone who can read that file can forge grants. Protect the data directory (mode `0700`) and the account that owns it.
- Atlas authorizes actions that an agent reports to it. It does not sandbox the agent or intercept actions the agent never submits.

## Supply chain

Releases are published from GitHub Actions with npm provenance (Trusted Publishing); verify with `npm view @corpussanctum/atlas-mcp dist.attestations`. 0.1.0 was published manually and has no provenance.
