export type PassportLayer =
  | "identity"
  | "doctrine"
  | "voice"
  | "offer"
  | "governance"
  | "state"
  | "evidence"
  | "manifest"
  | "interpreter"
  | "guide"
  | "config"
  | "runtime"
  | "custom";

export type FileVisibility = "public" | "operational" | "private";

export interface PassportFileEntry {
  path: string;
  layer: PassportLayer;
  mediaType: string;
  sha256: string;
  visibility: FileVisibility;
}

export interface PassportProfile {
  id: string;
  description: string;
  files: string[];
}

export interface ManifestSelfHashConfig {
  hashMode: "raw-bytes-with-own-sha256-replaced-by-64-zeroes";
  path: string;
  placeholder: string;
}

export interface LoadContract {
  bootstrap: string[];
  firstContext: string;
  then: string;
  duplicatesAllowed: boolean;
}

export interface TemporalInvariant {
  asOf: string;
}

export interface PassportManifest {
  schemaVersion: number;
  kind: "PASSPORT-CONTEXT";
  name: string;
  packageVersion: string;
  originator: string;
  technicalAuthority?: string;
  language: string;
  asOf: string;
  updatedAt: string;
  supersedes?: string;
  runtimeVerifiedAt: string | null;
  ownership: string;
  implicitMemory: boolean;
  authorityGrantedByPackage: boolean;
  hashAlgorithm: "sha256";
  hashEncoding: "lowercase-hex";
  hashByteContract: "UTF-8, LF line endings";
  manifestSelfHash: ManifestSelfHashConfig;
  loadContract: LoadContract;
  temporalInvariant?: TemporalInvariant;
  files: PassportFileEntry[];
  profiles: PassportProfile[];
}

export interface PassportReceipt {
  schemaVersion: number;
  kind: "passport-context-generation-receipt";
  status: "pass" | "fail";
  generatedAt: string;
  asOf: string;
  passport: {
    name: string;
    packageVersion: string;
    originator: string;
    technicalAuthority: string;
    manifestSha256: string;
    fileCount: number;
    files: Array<{
      path: string;
      layer: PassportLayer;
      sha256: string;
    }>;
  };
}

export interface IntegrityCheckResult {
  path: string;
  expectedHash: string;
  computedHash: string;
  matches: boolean;
  hasCRLF: boolean;
}

export interface IntegrityReport {
  valid: boolean;
  hasGitAttributes: boolean;
  hasCRLF: boolean;
  selfHashMatches: boolean;
  computedSelfHash: string;
  expectedSelfHash: string;
  fileChecks: IntegrityCheckResult[];
  errors: string[];
}
