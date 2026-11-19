package verify

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moshequantum/openpassport/internal/passport"
)

func copyDir(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.Walk(src, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, info.Mode())
	})
	if err != nil {
		t.Fatalf("copyDir failed: %v", err)
	}
}

func sealManifestForTest(t *testing.T, m *passport.PassportManifest) []byte {
	t.Helper()
	for i := range m.Files {
		if m.Files[i].Path == "manifest.json" {
			m.Files[i].Sha256 = passport.DefaultPlaceholder
		}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		t.Fatalf("encoding manifest: %v", err)
	}
	selfHash := passport.Sha256Bytes(passport.ToLF(buf.Bytes()))
	for i := range m.Files {
		if m.Files[i].Path == "manifest.json" {
			m.Files[i].Sha256 = selfHash
		}
	}
	buf.Reset()
	enc2 := json.NewEncoder(&buf)
	enc2.SetIndent("", "  ")
	enc2.SetEscapeHTML(false)
	if err := enc2.Encode(m); err != nil {
		t.Fatalf("re-encoding manifest: %v", err)
	}
	return passport.ToLF(buf.Bytes())
}

func TestVerify_GoldenTemplate(t *testing.T) {
	templateDir := filepath.Join("..", "..", "templates", "open-passport-template")
	rep, err := Verify(templateDir)
	if err != nil {
		t.Fatalf("expected golden template to verify cleanly, got: %v", err)
	}

	const expectedSelfHash = "b6d13a7447ba0abb914f54d338c92440acf5ab151615b5ef2260049c7b2fe5af"
	if rep.ComputedSelfHash != expectedSelfHash {
		t.Errorf("expected computed self hash %s, got %s", expectedSelfHash, rep.ComputedSelfHash)
	}
	if !rep.Valid {
		t.Errorf("expected report to be valid")
	}
	if len(rep.VerifiedFiles) != len(rep.Manifest.Files) {
		t.Errorf("expected %d verified files, got %d", len(rep.Manifest.Files), len(rep.VerifiedFiles))
	}
}

func TestVerify_TamperedFile(t *testing.T) {
	tmpDir := t.TempDir()
	templateDir := filepath.Join("..", "..", "templates", "open-passport-template")
	copyDir(t, templateDir, tmpDir)

	identityPath := filepath.Join(tmpDir, "01-IDENTITY.md")
	content, err := os.ReadFile(identityPath)
	if err != nil {
		t.Fatalf("reading 01-IDENTITY.md: %v", err)
	}

	if err := os.WriteFile(identityPath, append(content, []byte("\n# TAMPERED\n")...), 0644); err != nil {
		t.Fatalf("writing tampered file: %v", err)
	}

	rep, err := Verify(tmpDir)
	if err == nil {
		t.Fatal("expected error for tampered file, got nil")
	}
	if !strings.Contains(err.Error(), "01-IDENTITY.md") {
		t.Errorf("expected error to mention 01-IDENTITY.md, got %v", err)
	}
	if rep != nil && rep.Valid {
		t.Errorf("expected rep.Valid to be false")
	}
}

func TestVerify_TamperedSelfHash(t *testing.T) {
	tmpDir := t.TempDir()
	templateDir := filepath.Join("..", "..", "templates", "open-passport-template")
	copyDir(t, templateDir, tmpDir)

	manifestPath := filepath.Join(tmpDir, "manifest.json")
	content, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("reading manifest.json: %v", err)
	}

	corrupted := bytes.Replace(content, []byte("b6d13a7447ba0abb914f54d338c92440acf5ab151615b5ef2260049c7b2fe5af"), []byte("0000000000000000000000000000000000000000000000000000000000000001"), 1)
	if err := os.WriteFile(manifestPath, corrupted, 0644); err != nil {
		t.Fatalf("writing corrupted manifest: %v", err)
	}

	_, err = Verify(tmpDir)
	if err == nil {
		t.Fatal("expected error for tampered self-hash, got nil")
	}
	if !strings.Contains(err.Error(), "cryptographic seal mismatch") {
		t.Errorf("expected seal mismatch error, got %v", err)
	}
}

func TestVerify_RejectsPathTraversal(t *testing.T) {
	root := t.TempDir()
	baseDir := filepath.Join(root, "passport")
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		t.Fatalf("mkdir base: %v", err)
	}
	copyDir(t, filepath.Join("..", "..", "templates", "open-passport-template"), baseDir)

	secretBytes := []byte("top-secret-outside-passport\n")
	if err := os.WriteFile(filepath.Join(root, "secret.txt"), secretBytes, 0644); err != nil {
		t.Fatalf("writing secret.txt: %v", err)
	}

	manifestPath := filepath.Join(baseDir, "manifest.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("reading manifest: %v", err)
	}
	var m passport.PassportManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshaling manifest: %v", err)
	}
	m.Files = append(m.Files, passport.PassportFileEntry{
		Path:       "../secret.txt",
		Layer:      "custom",
		MediaType:  "text/plain",
		Sha256:     passport.Sha256Bytes(secretBytes),
		Visibility: "public",
	})
	if err := os.WriteFile(manifestPath, sealManifestForTest(t, &m), 0644); err != nil {
		t.Fatalf("writing sealed traversal manifest: %v", err)
	}

	rep, err := Verify(baseDir)
	if err == nil {
		t.Fatal("expected Verify to reject ../secret.txt traversal, got nil")
	}
	if rep != nil && rep.Valid {
		t.Fatal("expected rep.Valid to be false on path traversal")
	}
	if !strings.Contains(err.Error(), "security violation") && !strings.Contains(err.Error(), "traversal") {
		t.Errorf("expected security violation/traversal error, got: %v", err)
	}
}

func TestVerify_BinaryPNGWithCRByte(t *testing.T) {
	tmpDir := t.TempDir()
	if err := passport.InitPassport(tmpDir, "Binary Verify", "Tester"); err != nil {
		t.Fatalf("InitPassport: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(tmpDir, "assets"), 0755); err != nil {
		t.Fatalf("mkdir assets: %v", err)
	}

	pngBytes := []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x0d, 'I', 'H', 'D', 'R'}
	if err := os.WriteFile(filepath.Join(tmpDir, "assets", "logo.png"), pngBytes, 0644); err != nil {
		t.Fatalf("write png: %v", err)
	}

	if _, err := passport.BuildPassport(tmpDir, passport.BuildOptions{
		Name:       "Binary Verify",
		Originator: "Tester",
		AsOf:       "2026-11-18",
	}); err != nil {
		t.Fatalf("BuildPassport: %v", err)
	}

	rep, err := Verify(tmpDir)
	if err != nil {
		t.Fatalf("Verify failed on binary PNG containing 0x0d: %v", err)
	}
	if !rep.Valid {
		t.Fatalf("expected rep.Valid=true, errors=%v", rep.Errors)
	}
	if len(rep.VerifiedFiles) != len(rep.Manifest.Files) {
		t.Fatalf("expected %d verified files, got %d", len(rep.Manifest.Files), len(rep.VerifiedFiles))
	}
}

func TestVerify_RejectsCRLFInMarkdown(t *testing.T) {
	tmpDir := t.TempDir()
	if err := passport.InitPassport(tmpDir, "CRLF Verify", "Tester"); err != nil {
		t.Fatalf("InitPassport: %v", err)
	}

	// Write CRLF into 01-IDENTITY.md BEFORE BuildPassport (without AutoFixCRLF),
	// so the manifest hash actually matches the CRLF bytes on disk!
	// Verify must STILL reject CRLF on .md per the fail-closed LF contract.
	if err := os.WriteFile(filepath.Join(tmpDir, "01-IDENTITY.md"), []byte("# Identity\r\n\r\nBody\r\n"), 0644); err != nil {
		t.Fatalf("writing CRLF markdown: %v", err)
	}
	if _, err := passport.BuildPassport(tmpDir, passport.BuildOptions{
		Name:        "CRLF Verify",
		Originator:  "Tester",
		AsOf:        "2026-11-18",
		AutoFixCRLF: false,
	}); err != nil {
		t.Fatalf("BuildPassport: %v", err)
	}

	rep, err := Verify(tmpDir)
	if err == nil {
		t.Fatal("expected Verify to reject CRLF in 01-IDENTITY.md even when hash matched raw CRLF bytes")
	}
	if rep != nil && rep.Valid {
		t.Fatal("expected rep.Valid to be false")
	}
	if !strings.Contains(err.Error(), "CRLF") {
		t.Errorf("expected CRLF error message, got: %v", err)
	}
}

func TestVerify_RejectsInvalidHex64(t *testing.T) {
	tmpDir := t.TempDir()
	copyDir(t, filepath.Join("..", "..", "templates", "open-passport-template"), tmpDir)

	manifestPath := filepath.Join(tmpDir, "manifest.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("reading manifest: %v", err)
	}
	var m passport.PassportManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshaling manifest: %v", err)
	}

	m.Files[0].Sha256 = ""
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		t.Fatalf("encoding manifest: %v", err)
	}
	if err := os.WriteFile(manifestPath, passport.ToLF(buf.Bytes()), 0644); err != nil {
		t.Fatalf("writing manifest: %v", err)
	}

	rep, err := Verify(tmpDir)
	if err == nil {
		t.Fatal("expected Verify to fail closed on empty manifest sha256")
	}
	if rep != nil && rep.Valid {
		t.Fatal("expected rep.Valid to be false")
	}
}
