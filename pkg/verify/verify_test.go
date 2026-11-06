package verify

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
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

func TestVerify_GoldenTemplate(t *testing.T) {
	templateDir := filepath.Join("..", "..", "templates", "open-passport-template")
	rep, err := Verify(templateDir)
	if err != nil {
		t.Fatalf("expected golden template to verify cleanly, got: %v", err)
	}

	const expectedSelfHash = "35a9fea4f93b0da51284c57f9dbd7dab7140dc4ab702176b9f23ca2269519d92"
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

	corrupted := bytes.Replace(content, []byte("35a9fea4f93b0da51284c57f9dbd7dab7140dc4ab702176b9f23ca2269519d92"), []byte("0000000000000000000000000000000000000000000000000000000000000001"), 1)
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
