# Releasing

**History:** 0.1.0 was published manually (`npm publish` from a local machine as the `corpussanctum` npm user, commit `9da1d3f`). It has **no provenance attestation**. Releases from 0.1.1 on go through CI.

## Cut a release

1. Bump `version` in `package.json` and both `version` fields in `server.json`.
2. `npm test`, commit, push to `main`.
3. `git tag vX.Y.Z && git push origin vX.Y.Z`.
4. `.github/workflows/publish.yml` checks the tag against both files, runs the tests, and runs `npm publish --provenance --access public`.
5. Publish to the MCP Registry afterwards with `mcp-publisher` (needs the maintainer's GitHub OAuth; not automated).

## One-time setup

- Add an npm automation token (publish scope for `@corpussanctum/atlas-mcp`) as the repo secret `NPM_TOKEN`.
- Repo settings > Code security: enable secret scanning and push protection (free for public repos). Optionally Dependabot alerts.
- CodeQL runs from `.github/workflows/codeql.yml` (push, PR, weekly).
