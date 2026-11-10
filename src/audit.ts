import {
  appendFileSync, closeSync, existsSync, fstatSync, linkSync, mkdirSync, openSync, readFileSync, renameSync, statSync, truncateSync, unlinkSync, writeFileSync,
} from "node:fs";
import { hostname } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
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
  /** Set when the log verifies but something about it deserves a look. */
  warning?: string;
}

/** The signed pointer to the newest entry, kept beside the log so a shortened log is noticed. */
interface Head {
  seq: number;
  hash: string;
  signature: string;
}

interface Loaded {
  entries: AuditEntry[];
  /** Byte length of the complete, newline-terminated part of the file. */
  goodBytes: number;
  /** The file ends in an unterminated line: a write that was interrupted. */
  torn: boolean;
  /** 1-based line number of the first line that is not a JSON entry. */
  corruptLine?: number;
}

/** How long a waiter keeps trying for the lock. Longer than LOCK_STALE_MS, so a dead holder is always outlived. */
const LOCK_WAIT_MS = 15_000;
/** Age after which a lock is taken from a holder that cannot be shown to be dead. */
const LOCK_STALE_MS = 10_000;

/**
 * Append-only JSONL log: SHA3-256 hash chain, each entry signed with ML-DSA-65.
 * A signed head file (audit.head) records the newest entry, so removing entries
 * from the end of the log is detected as long as the head file survives.
 */
export class AuditLog {
  readonly path: string;
  readonly headPath: string;
  private readonly lock: string;
  private cache?: { size: number; mtimeMs: number; ctimeMs: number; ino: number; loaded: Loaded };

  constructor(dataDir: string, private readonly issuer: Issuer) {
    mkdirSync(dataDir, { recursive: true, mode: 0o700 });
    this.path = join(dataDir, "audit.jsonl");
    this.headPath = join(dataDir, "audit.head");
    this.lock = join(dataDir, "audit.lock");
  }

  /**
   * Every complete entry. A trailing line cut off by an interrupted write is
   * left out (it was never acknowledged); any other unreadable line throws.
   * The array is shared between calls: do not mutate it.
   */
  read(): AuditEntry[] {
    const l = this.load();
    if (l.corruptLine) throw new Error(`audit log is corrupt at line ${l.corruptLine}; run: atlas-mcp verify`);
    return l.entries;
  }

  append(type: EntryType, data: Record<string, unknown>): AuditEntry {
    return this.withLock(() => {
      const loaded = this.load();
      const entries = this.read();
      const last = entries[entries.length - 1];
      // Refuse to build on a log that no longer contains its signed head: appending would bury the evidence.
      const broken = this.checkHead(entries);
      if (broken) throw new Error(`audit log failed its integrity check (${broken}); run: atlas-mcp verify`);
      // Drop the remains of an interrupted write so the new entry starts on its own line.
      if (loaded.torn) truncateSync(this.path, loaded.goodBytes);

      const body = {
        seq: last ? last.seq + 1 : 1,
        ts: new Date().toISOString(),
        type,
        data,
        prev_hash: last ? last.hash : GENESIS,
      };
      const hash = sha3(canonical(body));
      const entry: AuditEntry = { ...body, hash, signature: this.issuer.sign(hash) };
      const line = JSON.stringify(entry) + "\n";
      appendFileSync(this.path, line, { mode: 0o600 });
      this.writeHead(entry);
      this.remember(loaded, entry, loaded.goodBytes + Buffer.byteLength(line));
      return entry;
    });
  }

  verify(): VerifyResult {
    // Verification must judge the bytes on disk, never a remembered parse: file metadata can be put back after an edit.
    const l = this.load(true);
    const entries = l.entries;
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
    if (l.corruptLine) return { valid: false, entries: entries.length, broken_at: l.corruptLine, reason: `line ${l.corruptLine} is not a valid audit entry` };
    const broken = this.checkHead(entries);
    if (broken) return { valid: false, entries: entries.length, broken_at: entries.length + 1, reason: broken };

    const warnings: string[] = [];
    if (l.torn) warnings.push("the log ends in an incomplete line from an interrupted write; it is ignored and removed by the next append");
    if (entries.length && !existsSync(this.headPath)) warnings.push("no signed head (audit.head) yet, so entries removed from the end of the log could not be detected; the next append writes one");
    return { valid: true, entries: entries.length, ...(warnings.length ? { warning: warnings.join("; ") } : {}) };
  }

  /** Parse the log, reusing the previous parse while the file is unchanged (unless `fresh`). */
  private load(fresh = false): Loaded {
    // Stat and read through one descriptor, so the cache key describes the same file the bytes came from.
    let fd: number;
    try { fd = openSync(this.path, "r"); } catch { return { entries: [], goodBytes: 0, torn: false }; }
    let st, raw: Buffer;
    try {
      st = fstatSync(fd);
      const c = this.cache;
      if (!fresh && c && c.size === st.size && c.mtimeMs === st.mtimeMs && c.ctimeMs === st.ctimeMs && c.ino === st.ino) return c.loaded;
      raw = readFileSync(fd);
    } finally {
      closeSync(fd);
    }
    const end = raw.lastIndexOf(0x0a) + 1; // bytes up to and including the last newline
    const loaded: Loaded = { entries: [], goodBytes: end, torn: end < raw.length };
    const lines = raw.subarray(0, end).toString("utf-8").split("\n");
    lines.pop(); // the empty string after the final newline
    for (const [i, line] of lines.entries()) {
      if (!line) continue;
      const e = parseEntry(line);
      if (!e) { loaded.corruptLine = i + 1; break; }
      loaded.entries.push(e);
    }
    this.cache = { size: st.size, mtimeMs: st.mtimeMs, ctimeMs: st.ctimeMs, ino: st.ino, loaded };
    return loaded;
  }

  /** Keep the parse current after our own append, so a long-lived server does not re-read the whole log each time. */
  private remember(loaded: Loaded, entry: AuditEntry, expectedSize: number): void {
    this.cache = undefined;
    if (loaded.torn || loaded.corruptLine) return;
    const st = statSync(this.path);
    if (st.size !== expectedSize) return; // someone else wrote too: re-read next time
    loaded.entries.push(entry);
    loaded.goodBytes = st.size;
    this.cache = { size: st.size, mtimeMs: st.mtimeMs, ctimeMs: st.ctimeMs, ino: st.ino, loaded };
  }

  /**
   * Compare the log with its signed head. The log may run ahead of the head
   * (a crash between the two writes) but must still contain the head's entry.
   * A missing head file is accepted: logs written before 0.1.2 have none.
   */
  private checkHead(entries: AuditEntry[]): string | undefined {
    let text: string;
    try {
      text = readFileSync(this.headPath, "utf-8");
    } catch (err) {
      return (err as NodeJS.ErrnoException).code === "ENOENT" ? undefined : "audit.head is unreadable";
    }
    let head: Head;
    try { head = JSON.parse(text) as Head; } catch { return "audit.head is unreadable"; }
    if (!head || !Number.isInteger(head.seq) || typeof head.hash !== "string" || typeof head.signature !== "string"
      || !this.issuer.verify(canonical({ seq: head.seq, hash: head.hash }), head.signature)) {
      return "audit.head has an invalid signature";
    }
    if (head.seq > entries.length) return `log is truncated: the signed head is entry ${head.seq}, but the log holds ${entries.length}`;
    if (entries[head.seq - 1].hash !== head.hash) return `entry ${head.seq} does not match the signed head (log rewritten)`;
    return undefined;
  }

  private writeHead(entry: AuditEntry): void {
    const head: Head = { seq: entry.seq, hash: entry.hash, signature: this.issuer.sign(canonical({ seq: entry.seq, hash: entry.hash })) };
    const tmp = `${this.headPath}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify(head) + "\n", { mode: 0o600 });
    renameSync(tmp, this.headPath);
  }

  private withLock<T>(fn: () => T): T {
    const token = `${hostname()}:${process.pid}:${randomBytes(6).toString("hex")}`;
    const deadline = Date.now() + LOCK_WAIT_MS;
    for (;;) {
      try {
        writeFileSync(this.lock, token, { flag: "wx", mode: 0o600 });
        break;
      } catch {
        this.stealIfStale();
        if (Date.now() > deadline) throw new Error("audit log is locked");
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 20);
      }
    }
    try {
      return fn();
    } finally {
      // Only remove the lock if it is still ours: it may have been taken from us as stale.
      try { if (readFileSync(this.lock, "utf-8") === token) unlinkSync(this.lock); } catch { /* already gone */ }
    }
  }

  /**
   * Remove the lock if its holder is gone: at once when the holder was a
   * process on this host that no longer exists, otherwise after LOCK_STALE_MS.
   * The lock is renamed away first and checked afterwards, so two waiters
   * cannot both take it, and a live lock grabbed by mistake is put back.
   */
  private stealIfStale(): void {
    try {
      const seen = readFileSync(this.lock, "utf-8");
      const [host, pid] = seen.split(":");
      const dead = host === hostname() && /^\d+$/.test(pid ?? "") && !isAlive(Number(pid));
      if (!dead && Date.now() - statSync(this.lock).mtimeMs <= LOCK_STALE_MS) return;
      const aside = `${this.lock}.${process.pid}.${randomBytes(4).toString("hex")}`;
      renameSync(this.lock, aside);
      if (readFileSync(aside, "utf-8") !== seen) {
        try { linkSync(aside, this.lock); } catch { /* someone else holds a newer lock */ }
      }
      unlinkSync(aside);
    } catch { /* raced with another process; retry on the next pass */ }
  }
}

function parseEntry(line: string): AuditEntry | undefined {
  try {
    const e = JSON.parse(line) as AuditEntry;
    const ok = e && typeof e === "object" && typeof e.seq === "number" && typeof e.type === "string" && typeof e.hash === "string"
      && typeof e.prev_hash === "string" && typeof e.signature === "string" && e.data !== null && typeof e.data === "object";
    return ok ? e : undefined;
  } catch {
    return undefined;
  }
}

function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "EPERM"; // exists, but owned by someone else
  }
}
