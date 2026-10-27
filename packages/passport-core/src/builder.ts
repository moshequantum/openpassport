import fs from "node:fs";
import path from "node:path";
import { PassportManifest, PassportReceipt, PassportLayer, PassportFileEntry } from "./types.js";
import { toLF, hasCRLF, CANONICAL_GITATTRIBUTES, isBinaryBuffer } from "./normalizer.js";
import { sha256, computeManifestSelfHash, DEFAULT_SELF_HASH_PLACEHOLDER } from "./hasher.js";

export interface BuildPassportOptions {
  name: string;
  packageVersion?: string;
  originator: string;
  technicalAuthority?: string;
  language?: string;
  asOf?: string;
  autoFixCRLF?: boolean;
}

function detectLayer(fileName: string): PassportLayer {
  if (fileName.startsWith("01-IDENTITY")) return "identity";
  if (fileName.startsWith("02-DOCTRINE")) return "doctrine";
  if (fileName.startsWith("03-VOICE")) return "voice";
  if (fileName.startsWith("04-OFFER")) return "offer";
  if (fileName.startsWith("05-GOVERNANCE")) return "governance";
  if (fileName.startsWith("06-CURRENT-STATE")) return "state";
  if (fileName.startsWith("07-EVIDENCE")) return "evidence";
  if (fileName === "MASTER-PROMPT.md") return "interpreter";
  if (fileName === "README.md") return "guide";
  if (fileName === ".gitattributes") return "config";
  if (fileName === "manifest.json") return "manifest";
  if (fileName.includes("runtime")) return "runtime";
  return "custom";
}

function detectMediaType(fileName: string): string {
  if (fileName.endsWith(".md")) return "text/markdown";
  if (fileName.endsWith(".json")) return "application/json";
  if (fileName.endsWith(".png")) return "image/png";
  if (fileName.endsWith(".svg")) return "image/svg+xml";
  if (fileName.endsWith(".pdf")) return "application/pdf";
  return "text/plain";
}

function getAllFiles(dir: string, baseDir: string = dir): string[] {
  let results: string[] = [];
  const list = fs.readdirSync(dir);
  for (const item of list) {
    if (item === ".git" || item === "generation.receipt.json") continue;
    const full = path.join(dir, item);
    const stat = fs.statSync(full);
    if (stat.isDirectory()) {
      results = results.concat(getAllFiles(full, baseDir));
    } else {
      results.push(path.relative(baseDir, full).replace(/\\/g, "/"));
    }
  }
  return results;
}

/**
 * Deterministically builds, compiles, and cryptographically seals an OpenPassport directory.
 */
export function buildPassport(
  baseDir: string,
  options: BuildPassportOptions
): { manifest: PassportManifest; receipt: PassportReceipt; manifestSelfHash: string } {
  const asOf = options.asOf || new Date().toISOString().split("T")[0];
  const gitattributesPath = path.join(baseDir, ".gitattributes");
  if (!fs.existsSync(gitattributesPath)) {
    fs.writeFileSync(gitattributesPath, toLF(CANONICAL_GITATTRIBUTES), "utf8");
  }

  // 1. Gather all files
  const relativeFiles = getAllFiles(baseDir);
  if (!relativeFiles.includes("manifest.json")) {
    relativeFiles.push("manifest.json");
  }

  // 2. Normalization & Hashing
  const fileEntries: PassportFileEntry[] = [];

  for (const relPath of relativeFiles) {
    if (relPath === "manifest.json") continue;

    const fullPath = path.join(baseDir, relPath);
    let buf = fs.readFileSync(fullPath);

    // Auto fix CRLF on text files if option enabled
    if (options.autoFixCRLF && !isBinaryBuffer(buf) && hasCRLF(buf)) {
      const normalized = toLF(buf.toString("utf8"));
      fs.writeFileSync(fullPath, normalized, "utf8");
      buf = Buffer.from(normalized, "utf8");
    }

    const hash = sha256(buf);
    const layer = detectLayer(path.basename(relPath));
    const mediaType = detectMediaType(relPath);
    const visibility = relPath.startsWith("private") ? "private" : "public";

    fileEntries.push({
      path: relPath,
      layer,
      mediaType,
      sha256: hash,
      visibility,
    });
  }

  // 3. Construct Manifest
  const manifest: PassportManifest = {
    schemaVersion: 1,
    kind: "PASSPORT-CONTEXT",
    name: options.name,
    packageVersion: options.packageVersion || "1.0.0",
    originator: options.originator,
    technicalAuthority: options.technicalAuthority || "Founding AI Product Engineer / Design Engineer",
    language: options.language || "es",
    asOf,
    updatedAt: asOf,
    runtimeVerifiedAt: null,
    ownership: "originator-owned",
    implicitMemory: false,
    authorityGrantedByPackage: false,
    hashAlgorithm: "sha256",
    hashEncoding: "lowercase-hex",
    hashByteContract: "UTF-8, LF line endings",
    manifestSelfHash: {
      hashMode: "raw-bytes-with-own-sha256-replaced-by-64-zeroes",
      path: "manifest.json",
      placeholder: DEFAULT_SELF_HASH_PLACEHOLDER,
    },
    loadContract: {
      bootstrap: ["manifest.json"],
      firstContext: "MASTER-PROMPT.md",
      then: "profiles[].files in listed order",
      duplicatesAllowed: false,
    },
    temporalInvariant: { asOf },
    files: [
      {
        path: "manifest.json",
        layer: "manifest",
        mediaType: "application/json",
        sha256: DEFAULT_SELF_HASH_PLACEHOLDER,
        visibility: "public",
      },
      ...fileEntries.sort((a, b) => a.path.localeCompare(b.path)),
    ],
    profiles: [
      {
        id: "core-public",
        description: "Public identity, doctrine, and voice guidelines",
        files: fileEntries
          .filter((f) => f.visibility === "public" && ["identity", "doctrine", "voice", "interpreter", "guide"].includes(f.layer))
          .map((f) => f.path),
      },
      {
        id: "full",
        description: "Complete canonical passport package",
        files: fileEntries.map((f) => f.path),
      },
    ],
  };

  // 4. Compute and seal manifest self-hash
  const { selfHash } = computeManifestSelfHash(manifest);
  const manifestEntry = manifest.files.find((f) => f.path === "manifest.json");
  if (manifestEntry) {
    manifestEntry.sha256 = selfHash;
  }

  const manifestPath = path.join(baseDir, "manifest.json");
  fs.writeFileSync(manifestPath, toLF(JSON.stringify(manifest, null, 2)), "utf8");

  // 5. Generate generation.receipt.json
  const receipt: PassportReceipt = {
    schemaVersion: 1,
    kind: "passport-context-generation-receipt",
    status: "pass",
    generatedAt: new Date().toISOString(),
    asOf,
    passport: {
      name: manifest.name,
      packageVersion: manifest.packageVersion,
      originator: manifest.originator,
      technicalAuthority: manifest.technicalAuthority || "Founding AI Product Engineer / Design Engineer",
      manifestSha256: selfHash,
      fileCount: manifest.files.length,
      files: manifest.files.map((f) => ({
        path: f.path,
        layer: f.layer,
        sha256: f.sha256,
      })),
    },
  };

  const receiptPath = path.join(baseDir, "generation.receipt.json");
  fs.writeFileSync(receiptPath, toLF(JSON.stringify(receipt, null, 2)), "utf8");

  return {
    manifest,
    receipt,
    manifestSelfHash: selfHash,
  };
}
