import { matchGlob } from "./glob.js";

/**
 * Action names are identifiers, not arbitrary strings. Callers may write them
 * in any case or with surrounding whitespace, but the policy language treats
 * `DB.DELETE`, `db.delete ` and `db.delete` as the same action. Normalizing on
 * both sides keeps a deny rule from being bypassed by spelling changes.
 *
 * Resource and environment patterns are deliberately NOT normalized here: they
 * may be case-sensitive (paths, URLs, table names) and have their own matching.
 */
const ACTION_RE = /^[a-z0-9][a-z0-9_./-]*$/;

export function normalizeAction(value: string): string {
  return (value ?? "").trim().toLowerCase();
}

/** Returns the canonical form, or undefined when the value is not an action identifier. */
export function canonicalAction(value: string): string | undefined {
  const a = normalizeAction(value);
  return ACTION_RE.test(a) ? a : undefined;
}

/** Like `matchAny`, but case- and whitespace-insensitive on both pattern and value. */
export function matchAction(patterns: readonly string[], action: string): string | undefined {
  const a = normalizeAction(action);
  return patterns.find((p) => matchGlob(normalizeAction(p), a));
}
