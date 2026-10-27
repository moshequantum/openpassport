import { describe, it } from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import {
  toLF,
  hasCRLF,
  sha256,
  computeManifestSelfHash,
  buildPassport,
  verifyPassportIntegrity,
  validateSevenLayers,
} from "../dist/index.js";

describe("@multiversa/passport-core", () => {
  it("normalizes CRLF to LF correctly", () => {
    const dirty = "hello\r\nworld\r\n";
    const clean = toLF(dirty);
    assert.strictEqual(clean, "hello\nworld\n");
    assert.strictEqual(hasCRLF(clean), false);
    assert.strictEqual(hasCRLF(dirty), true);
  });

  it("calculates deterministic SHA-256", () => {
    const hash = sha256("test-content\n");
    assert.strictEqual(typeof hash, "string");
    assert.strictEqual(hash.length, 64);
  });

  it("builds and verifies a canonical passport", () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "passport-test-"));
    try {
      // Create minimal layers
      fs.writeFileSync(path.join(tmpDir, "01-IDENTITY.md"), "# 01 Identity\n", "utf8");
      fs.writeFileSync(path.join(tmpDir, "02-DOCTRINE.md"), "# 02 Doctrine\n", "utf8");
      fs.writeFileSync(path.join(tmpDir, "03-VOICE.md"), "# 03 Voice\n", "utf8");
      fs.writeFileSync(path.join(tmpDir, "04-OFFER.md"), "# 04 Offer\n", "utf8");
      fs.writeFileSync(path.join(tmpDir, "05-GOVERNANCE.md"), "# 05 Governance\n", "utf8");
      fs.writeFileSync(path.join(tmpDir, "06-CURRENT-STATE.md"), "# 06 State\n", "utf8");
      fs.writeFileSync(path.join(tmpDir, "07-EVIDENCE.md"), "# 07 Evidence\n", "utf8");
      fs.writeFileSync(path.join(tmpDir, "MASTER-PROMPT.md"), "# Master Prompt\n", "utf8");
      fs.writeFileSync(path.join(tmpDir, "README.md"), "# Readme\n", "utf8");

      const layersCheck = validateSevenLayers(tmpDir);
      assert.strictEqual(layersCheck.missing.length, 0);

      const result = buildPassport(tmpDir, {
        name: "Test Passport",
        originator: "Multiversa Lab Tester",
        asOf: "2026-09-29",
      });

      assert.strictEqual(result.manifest.kind, "PASSPORT-CONTEXT");
      assert.strictEqual(typeof result.manifestSelfHash, "string");
      assert.strictEqual(result.manifestSelfHash.length, 64);

      // Verify integrity
      const audit = verifyPassportIntegrity(tmpDir);
      assert.strictEqual(audit.valid, true);
      assert.strictEqual(audit.selfHashMatches, true);
      assert.strictEqual(audit.hasCRLF, false);
      assert.strictEqual(audit.hasGitAttributes, true);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
