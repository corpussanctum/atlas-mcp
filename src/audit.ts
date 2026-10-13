import { appendFileSync, closeSync, existsSync, mkdirSync, openSync, readFileSync, statSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import { canonical, sha3 } from "./canonical.js";
import type { Issuer } from "./keys.js";

export type EntryType = "GRANT" | "REVOKE" | "AUTHORIZE" | "RESOLVE" | "COMMIT";

export interface AuditEntry {
  seq: number;
  ts: string;
  type: EntryType;
  data: Record<string, unknown>;
  prev_hash: string;
  hash: string;
  signature: string;
}

const GENESIS = "0".repeat(64);

export interface VerifyResult {
  valid: boolean;
  entries: number;
  broken_at?: number;
  reason?: string;
}

/** Append-only JSONL log: SHA3-256 hash chain, each entry signed with ML-DSA-65. */
export class AuditLog {
  readonly path: string;
  private readonly lock: string;

  constructor(dataDir: string, private readonly issuer: Issuer) {
    mkdirSync(dataDir, { recursive: true, mode: 0o700 });
    this.path = join(dataDir, "audit.jsonl");
    this.lock = join(dataDir, "audit.lock");
  }

  read(): AuditEntry[] {
    if (!existsSync(this.path)) return [];
    return readFileSync(this.path, "utf-8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as AuditEntry);
  }

  append(type: EntryType, data: Record<string, unknown>): AuditEntry {
    return this.withLock(() => {
      const entries = this.read();
      const last = entries[entries.length - 1];
      const body = {
        seq: last ? last.seq + 1 : 1,
        ts: new Date().toISOString(),
        type,
        data,
        prev_hash: last ? last.hash : GENESIS,
      };
      const hash = sha3(canonical(body));
      const entry: AuditEntry = { ...body, hash, signature: this.issuer.sign(hash) };
      appendFileSync(this.path, JSON.stringify(entry) + "\n", { mode: 0o600 });
      return entry;
    });
  }

  verify(): VerifyResult {
    const entries = this.read();
    let prev = GENESIS;
    for (const [i, e] of entries.entries()) {
      const fail = (reason: string): VerifyResult => ({ valid: false, entries: entries.length, broken_at: e.seq, reason });
      if (e.seq !== i + 1) return fail("sequence gap");
      if (e.prev_hash !== prev) return fail("prev_hash mismatch (entry removed or reordered)");
      const { hash, signature, ...body } = e;
      if (sha3(canonical(body)) !== hash) return fail("hash mismatch (entry modified)");
      if (!this.issuer.verify(hash, signature)) return fail("invalid ML-DSA-65 signature");
      prev = hash;
    }
    return { valid: true, entries: entries.length };
  }

  private withLock<T>(fn: () => T): T {
    const deadline = Date.now() + 5000;
    for (;;) {
      try {
        closeSync(openSync(this.lock, "wx"));
        break;
      } catch {
        try {
          if (Date.now() - statSync(this.lock).mtimeMs > 10_000) unlinkSync(this.lock);
        } catch { /* raced with another process */ }
        if (Date.now() > deadline) throw new Error("audit log is locked");
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 20);
      }
    }
    try {
      return fn();
    } finally {
      try { unlinkSync(this.lock); } catch { /* already gone */ }
    }
  }
}
