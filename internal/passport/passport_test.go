package passport

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type GoldenVector struct {
	ID               string   `json:"id"`
	Description      string   `json:"description"`
	Raw              string   `json:"raw"`
	Sha256           string   `json:"sha256"`
	IsCanonicalLF    bool     `json:"isCanonicalLF"`
	NormalizedSha256 string   `json:"normalizedSha256"`
	OrderedKeys      []string `json:"orderedKeys"`
}

type GoldenManifest struct {
	Vectors []GoldenVector `json:"vectors"`
}

func copyDir(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
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

func TestVectorsConformance(t *testing.T) {
	manifestPath := filepath.Join("..", "..", "testdata", "vectors", "manifest.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("reading golden vectors manifest: %v", err)
	}

	var gm GoldenManifest
	if err := json.Unmarshal(data, &gm); err != nil {
		t.Fatalf("unmarshaling golden vectors: %v", err)
	}

	for _, v := range gm.Vectors {
		t.Run(v.ID, func(t *testing.T) {
			if v.Raw != "" {
				h := Sha256Bytes([]byte(v.Raw))
				if h != v.Sha256 {
					t.Errorf("[%s] hash mismatch: got %s, want %s", v.ID, h, v.Sha256)
				}
				if v.IsCanonicalLF && HasCRLF([]byte(v.Raw)) {
					t.Errorf("[%s] expected canonical LF but HasCRLF is true", v.ID)
				}
				if v.NormalizedSha256 != "" {
					normalized := ToLF([]byte(v.Raw))
					nh := Sha256Bytes(normalized)
					if nh != v.NormalizedSha256 {
						t.Errorf("[%s] normalized hash mismatch: got %s, want %s", v.ID, nh, v.NormalizedSha256)
					}
				}
			}
		})
	}
}

func TestH2_NormalizeNoTrim(t *testing.T) {
	dirty := "   leading spaces and trailing   \r\n\r\n"
	normalized := string(ToLF([]byte(dirty)))
	expected := "   leading spaces and trailing   \n\n"
	if normalized != expected {
		t.Fatalf("ToLF performed trimming: got %q, want %q", normalized, expected)
	}
}

func TestB1_ExportRejectsTraversal(t *testing.T) {
	_, err := SafeJoin("/base/dir", "../secret.txt")
	if err == nil {
		t.Fatal("expected SafeJoin to reject path traversal with ..")
	}

	_, err = SafeJoin("/base/dir", "/etc/passwd")
	if err == nil {
		t.Fatal("expected SafeJoin to reject absolute path")
	}
}

func TestB2_ExportVerifiesIntegrityBeforePacking(t *testing.T) {
	tmpDir := t.TempDir()
	templateDir := filepath.Join("..", "..", "templates", "open-passport-template")
	copyDir(t, templateDir, tmpDir)

	// Tamper with a layer file
	tamperPath := filepath.Join(tmpDir, "01-IDENTITY.md")
	if err := os.WriteFile(tamperPath, []byte("# CORRUPTED\n"), 0644); err != nil {
		t.Fatalf("writing tampered file: %v", err)
	}

	bundlePath := filepath.Join(tmpDir, "bundle.tar.gz")
	err := ExportProfile(tmpDir, "core-public", bundlePath)
	if err == nil {
		t.Fatal("expected export to fail when passport integrity is violated")
	}
	if !strings.Contains(err.Error(), "pre-export verification failed") {
		t.Fatalf("expected error to mention pre-export verification, got: %v", err)
	}
}

func TestH4_ExportIsDeterministic(t *testing.T) {
	tmpDir := t.TempDir()
	templateDir := filepath.Join("..", "..", "templates", "open-passport-template")
	copyDir(t, templateDir, tmpDir)

	bundle1 := filepath.Join(tmpDir, "bundle1.tar.gz")
	bundle2 := filepath.Join(tmpDir, "bundle2.tar.gz")

	if err := ExportProfile(tmpDir, "core-public", bundle1); err != nil {
		t.Fatalf("export bundle1 failed: %v", err)
	}

	// Sleep slightly to guarantee different system wall-clock times
	time.Sleep(50 * time.Millisecond)

	if err := ExportProfile(tmpDir, "core-public", bundle2); err != nil {
		t.Fatalf("export bundle2 failed: %v", err)
	}

	// Compare uncompressed tar streams to verify determinism regardless of gzip header timestamp
	getTarBytes := func(p string) []byte {
		f, err := os.Open(p)
		if err != nil {
			t.Fatalf("reading %s: %v", p, err)
		}
		defer f.Close()
		gr, err := gzip.NewReader(f)
		if err != nil {
			t.Fatalf("gunzip %s: %v", p, err)
		}
		defer gr.Close()
		var buf bytes.Buffer
		_, err = io.Copy(&buf, gr)
		if err != nil {
			t.Fatalf("reading tar from %s: %v", p, err)
		}
		return buf.Bytes()
	}

	tar1 := getTarBytes(bundle1)
	tar2 := getTarBytes(bundle2)

	if !bytes.Equal(tar1, tar2) {
		t.Fatalf("non-deterministic export: tar streams are not byte-identical (tar1 len=%d, tar2 len=%d)", len(tar1), len(tar2))
	}

	// Verify tar headers have ModTime = 0 and UID/GID = 0
	tr := tar.NewReader(bytes.NewReader(tar1))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("reading tar header: %v", err)
		}
		if hdr.Uid != 0 || hdr.Gid != 0 {
			t.Errorf("tar entry %s UID/GID not zero: uid=%d, gid=%d", hdr.Name, hdr.Uid, hdr.Gid)
		}
		if !hdr.ModTime.IsZero() && hdr.ModTime.Unix() != 0 {
			t.Errorf("tar entry %s ModTime not zeroed: %v", hdr.Name, hdr.ModTime)
		}
	}
}

func TestH5_DeterministicBuildWithAsOf(t *testing.T) {
	tmpDir1 := t.TempDir()
	tmpDir2 := t.TempDir()

	opts := BuildOptions{
		Name:        "Test Passport",
		Originator:  "Tester",
		AsOf:        "2026-11-04",
		AutoFixCRLF: false,
	}

	if err := InitPassport(tmpDir1, opts.Name, opts.Originator); err != nil {
		t.Fatalf("init 1: %v", err)
	}
	if err := InitPassport(tmpDir2, opts.Name, opts.Originator); err != nil {
		t.Fatalf("init 2: %v", err)
	}

	m1, err := BuildPassport(tmpDir1, opts)
	if err != nil {
		t.Fatalf("build 1: %v", err)
	}

	m2, err := BuildPassport(tmpDir2, opts)
	if err != nil {
		t.Fatalf("build 2: %v", err)
	}

	if m1.Files[0].Sha256 != m2.Files[0].Sha256 {
		t.Fatalf("build not deterministic: selfHash1=%s, selfHash2=%s", m1.Files[0].Sha256, m2.Files[0].Sha256)
	}

	// Validate hex format
	if _, err := hex.DecodeString(m1.Files[0].Sha256); err != nil || len(m1.Files[0].Sha256) != 64 {
		t.Fatalf("invalid hex selfHash: %s", m1.Files[0].Sha256)
	}
}
