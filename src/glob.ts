/** `*` matches any run of characters (including separators). Case-sensitive. */
function toRegex(pattern: string): RegExp {
  const escaped = pattern.replace(/[.+^${}()|[\]\\?]/g, "\\$&").replace(/\*/g, ".*");
  return new RegExp(`^${escaped}$`, "s");
}

export function matchGlob(pattern: string, value: string): boolean {
  return toRegex(pattern).test(value);
}

export function matchAny(patterns: readonly string[], value: string): string | undefined {
  return patterns.find((p) => matchGlob(p, value));
}

/** True when parent pattern `parent` admits everything child pattern `child` could (child taken literally). */
export function covers(parent: string, child: string): boolean {
  return matchGlob(parent, child);
}
