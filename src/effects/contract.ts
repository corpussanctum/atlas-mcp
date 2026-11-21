import { canonical } from "../canonical.js";
import { matchGlob } from "../glob.js";

/**
 * An effect Atlas can reason about. Moved here so the engine, the enforcement
 * point and the reference adapters share one definition without an import
 * cycle. `engine.ts` re-exports it for existing callers.
 */
export interface Effect {
  /** read | write | create | delete | exec | send | spend ... free-form */
  type: string;
  /** What is touched, e.g. `postgres://prod/users`. */
  resource: string;
  /** e.g. `staging`, `production`. Required when any grant restricts environments. */
  environment?: string;
  irreversible?: boolean;
}

/**
 * F1 enforcement contract. In `declared` mode Atlas keeps its v0.1 behaviour:
 * the caller declares effects and later reports what it claims happened.
 *
 * In `observed` mode the receipt is bound to an exact operation and to the
 * enforcement point that derives effects from that operation. Committing
 * requires an attestation from that observer; declared-but-unobserved mutations
 * and observed-but-undeclared effects are both violations. Caller-supplied
 * `effects` alone can never satisfy an observed receipt.
 */
export type EnforcementMode = "declared" | "observed";

export interface EnforcementContract {
  mode: EnforcementMode;
  /** Stable id of the enforcement point, e.g. `atlas-sql-effects/1.0.0`. */
  observer?: string;
  /** Hex SHA3-256 of the canonical operation bound to this receipt. */
  operation_hash?: string;
}

export interface EffectAttestation {
  observer: string;
  operation_hash: string;
  /** Effects the observer independently derived/observed, not caller claims. */
  effects: Effect[];
  observed_at?: string;
  /** Optional ML-DSA-65 signature over `attestationPayload`. */
  signature?: string;
}

/** Server-side policy. Default is legacy `declared` mode. */
export interface EnforcementConfig {
  /** When `observed`, every authorize call must carry an observed contract. */
  mode?: EnforcementMode;
  /** Restrict which observer ids may issue authorizations/attestations. */
  trustedObservers?: string[];
  /** observer id -> base64 ML-DSA-65 public key. When set, signatures are required. */
  observerPublicKeys?: Record<string, string>;
}

export const DEFAULT_ENFORCEMENT: Readonly<EnforcementConfig> = { mode: "declared" };
export const OPERATION_HASH_RE = /^[0-9a-f]{64}$/;

/** Does an authorized (possibly globbed) effect cover an observed effect? */
export function effectCovers(declared: Effect, observed: Effect): boolean {
  return declared.type === observed.type
    && declared.environment === observed.environment
    && matchGlob(declared.resource, observed.resource);
}

/** Canonical identity of an effect for set comparisons. */
export function effectKey(effect: Effect): string {
  return canonical({
    type: effect.type,
    resource: effect.resource,
    environment: effect.environment ?? null,
  });
}

export function sameEffectSet(a: readonly Effect[], b: readonly Effect[]): boolean {
  const keys = (xs: readonly Effect[]) => xs.map(effectKey).sort();
  const ka = keys(a);
  const kb = keys(b);
  return ka.length === kb.length && ka.every((k, i) => k === kb[i]);
}

/** The exact bytes an observer signs (or an operator verifies). */
export function attestationPayload(a: Omit<EffectAttestation, "signature"> & { receipt_id: string }): string {
  return canonical({
    receipt_id: a.receipt_id,
    observer: a.observer,
    operation_hash: a.operation_hash,
    effects: a.effects,
    observed_at: a.observed_at ?? null,
  });
}
