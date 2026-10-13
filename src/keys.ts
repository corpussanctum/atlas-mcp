import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { createHash, randomBytes } from "node:crypto";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa";

/**
 * The Atlas issuer: an ML-DSA-65 keypair (FIPS 204) that signs grants and audit
 * entries. Stored at <dataDir>/issuer.json with mode 0600. v0.1 keeps the key
 * unwrapped on disk; protect the data dir like an SSH key.
 */
export class Issuer {
  private constructor(
    readonly publicKey: Uint8Array,
    private readonly secretKey: Uint8Array,
  ) {}

  static loadOrCreate(dataDir: string): Issuer {
    const path = join(dataDir, "issuer.json");
    if (existsSync(path)) {
      const j = JSON.parse(readFileSync(path, "utf-8"));
      return new Issuer(Buffer.from(j.public_key_b64, "base64"), Buffer.from(j.secret_key_b64, "base64"));
    }
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    const kp = ml_dsa65.keygen(randomBytes(32));
    writeFileSync(
      path,
      JSON.stringify({
        algorithm: "ML-DSA-65",
        public_key_b64: Buffer.from(kp.publicKey).toString("base64"),
        secret_key_b64: Buffer.from(kp.secretKey).toString("base64"),
        created_at: new Date().toISOString(),
      }),
      { mode: 0o600 },
    );
    chmodSync(path, 0o600);
    return new Issuer(kp.publicKey, kp.secretKey);
  }

  get keyId(): string {
    return createHash("sha256").update(this.publicKey).digest("hex").slice(0, 16);
  }

  sign(message: string): string {
    return Buffer.from(ml_dsa65.sign(this.secretKey, new TextEncoder().encode(message))).toString("base64");
  }

  verify(message: string, signatureB64: string): boolean {
    try {
      return ml_dsa65.verify(this.publicKey, new TextEncoder().encode(message), Buffer.from(signatureB64, "base64"));
    } catch {
      return false;
    }
  }
}
