import fs from "node:fs";
import path from "node:path";
import { PassportManifest, IntegrityReport, IntegrityCheckResult } from "./types.js";
import { hasCRLF, isBinaryBuffer } from "./normalizer.js";
import { sha256, computeManifestSelfHash, DEFAULT_SELF_HASH_PLACEHOLDER } from "./hasher.js";

export const CANONICAL_LAYERS = [
  "01-IDENTITY.md",
  "02-DOCTRINE.md",
  "03-VOICE.md",
  "04-OFFER.md",
  "05-GOVERNANCE.md",
  "06-CURRENT-STATE.md",
  "07-EVIDENCE.md",
];

export function validateSevenLayers(baseDir: string): { missing: string[]; present: string[] } {
  const missing: string[] = [];
  const present: string[] = [];

  for (const layer of CANONICAL_LAYERS) {
    const full = path.join(baseDir, layer);
    if (fs.existsSync(full)) {
      present.push(layer);
    } else {
      missing.push(layer);
    }
  }

  return { missing, present };
}

/**
 * Audits a passport-context directory against the OpenPassport v1.0 standard.
 */
export function verifyPassportIntegrity(baseDir: string): IntegrityReport {
  const errors: string[] = [];
  const fileChecks: IntegrityCheckResult[] = [];

  const manifestPath = path.join(baseDir, "manifest.json");
  if (!fs.existsSync(manifestPath)) {
    return {
      valid: false,
      hasGitAttributes: false,
      hasCRLF: false,
      selfHashMatches: false,
      computedSelfHash: "",
      expectedSelfHash: "",
      fileChecks: [],
      errors: ["manifest.json is missing"],
    };
  }

  const hasGitAttributes = fs.existsSync(path.join(baseDir, ".gitattributes"));
  if (!hasGitAttributes) {
    errors.push(".gitattributes is missing (required to prevent CRLF line ending corruption on Windows)");
  }

  const manifestContent = fs.readFileSync(manifestPath, "utf8");
  let manifest: PassportManifest;
  try {
    manifest = JSON.parse(manifestContent);
  } catch (err) {
    return {
      valid: false,
      hasGitAttributes,
      hasCRLF: hasCRLF(manifestContent),
      selfHashMatches: false,
      computedSelfHash: "",
      expectedSelfHash: "",
      fileChecks: [],
      errors: [`Failed to parse manifest.json: ${String(err)}`],
    };
  }

  const placeholder = manifest.manifestSelfHash?.placeholder || DEFAULT_SELF_HASH_PLACEHOLDER;
  const manifestEntry = manifest.files?.find((f) => f.path === "manifest.json");
  const expectedSelfHash = manifestEntry?.sha256 || "";
  
  const { selfHash: computedSelfHash } = computeManifestSelfHash(manifest, placeholder);
  const selfHashMatches = expectedSelfHash === computedSelfHash;
  if (!selfHashMatches) {
    errors.push(`manifestSelfHash mismatch: manifest has ${expectedSelfHash}, computed ${computedSelfHash}`);
  }

  let globalCRLF = false;

  for (const entry of manifest.files || []) {
    if (entry.path === "manifest.json") {
      fileChecks.push({
        path: entry.path,
        expectedHash: expectedSelfHash,
        computedHash: computedSelfHash,
        matches: selfHashMatches,
        hasCRLF: hasCRLF(manifestContent),
      });
      continue;
    }

    const filePath = path.join(baseDir, entry.path);
    if (!fs.existsSync(filePath)) {
      errors.push(`File missing on disk: ${entry.path}`);
      fileChecks.push({
        path: entry.path,
        expectedHash: entry.sha256,
        computedHash: "MISSING",
        matches: false,
        hasCRLF: false,
      });
      continue;
    }

    const buf = fs.readFileSync(filePath);
    const isBinary = isBinaryBuffer(buf);
    const fileHasCRLF = !isBinary && hasCRLF(buf);
    if (fileHasCRLF) {
      globalCRLF = true;
      errors.push(`CRLF detected in ${entry.path}! Must be normalized to pure LF.`);
    }

    const hash = sha256(buf);
    const matches = hash === entry.sha256;
    if (!matches) {
      errors.push(`Hash mismatch for ${entry.path}: expected ${entry.sha256}, got ${hash}`);
    }

    fileChecks.push({
      path: entry.path,
      expectedHash: entry.sha256,
      computedHash: hash,
      matches,
      hasCRLF: fileHasCRLF,
    });
  }

  return {
    valid: errors.length === 0,
    hasGitAttributes,
    hasCRLF: globalCRLF,
    selfHashMatches,
    computedSelfHash,
    expectedSelfHash,
    fileChecks,
    errors,
  };
}
