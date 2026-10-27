import { PassportManifest, PassportFileEntry } from "./types.js";

/**
 * Filters the passport files according to a designated security profile (e.g. core-public, commercial-public, full).
 */
export function filterProfile(
  manifest: PassportManifest,
  profileId: string
): { profileId: string; files: PassportFileEntry[] } {
  const profile = manifest.profiles?.find((p) => p.id === profileId);
  if (!profile) {
    throw new Error(`Profile '${profileId}' not found in manifest profiles.`);
  }

  const allowedPaths = new Set(profile.files);
  // Always include manifest.json and MASTER-PROMPT.md if available
  allowedPaths.add("manifest.json");
  if (manifest.files.some((f) => f.path === "MASTER-PROMPT.md")) {
    allowedPaths.add("MASTER-PROMPT.md");
  }

  const filteredFiles = manifest.files.filter((f) => allowedPaths.has(f.path));

  return {
    profileId,
    files: filteredFiles,
  };
}
