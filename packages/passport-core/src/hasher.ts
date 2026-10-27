import crypto from "node:crypto";
import { PassportManifest } from "./types.js";
import { toLF } from "./normalizer.js";

export const DEFAULT_SELF_HASH_PLACEHOLDER = "0".repeat(64);

/**
 * Computes the lowercase hex SHA-256 hash of a string or buffer.
 */
export function sha256(content: Buffer | string): string {
  if (Buffer.isBuffer(content)) {
    return crypto.createHash("sha256").update(content).digest("hex");
  }
  return crypto.createHash("sha256").update(content, "utf8").digest("hex");
}

/**
 * Breaks the circular dependency when hashing manifest.json.
 * 1. Clones the manifest object.
 * 2. Replaces manifest.json's own sha256 entry with 64 zeroes.
 * 3. Serializes to deterministic 2-space indented JSON with LF ending.
 * 4. Computes SHA-256 over those exact UTF-8 bytes.
 */
export function computeManifestSelfHash(
  manifest: PassportManifest,
  placeholder: string = DEFAULT_SELF_HASH_PLACEHOLDER
): { selfHash: string; normalizedContent: string } {
  const clone = JSON.parse(JSON.stringify(manifest)) as PassportManifest;
  
  const manifestEntry = clone.files.find((f) => f.path === "manifest.json");
  if (manifestEntry) {
    manifestEntry.sha256 = placeholder;
  }

  const jsonStringWithZeroes = toLF(JSON.stringify(clone, null, 2));
  const selfHash = sha256(Buffer.from(jsonStringWithZeroes, "utf8"));

  return {
    selfHash,
    normalizedContent: jsonStringWithZeroes,
  };
}
