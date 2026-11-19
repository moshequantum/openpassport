package passport

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
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

func TestIsTextFile(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"01-IDENTITY.md", true},
		{"manifest.json", true},
		{"notes.txt", true},
		{"visual/page.html", true},
		{".gitattributes", true},
		{"nested/.gitattributes", true},
		{"LICENSE", true},
		{"docs/LICENSE", true},
		{"README.MD", true},
		{"config.JSON", true},
		{"assets/logo.png", false},
		{"assets/photo.jpg", false},
		{"docs/spec.pdf", false},
		{"assets/banner.svg", false},
		{"fonts/inter.woff2", false},
		{"bundle.tar.gz", false},
	}

	for _, tc := range cases {
		if got := IsTextFile(tc.path); got != tc.want {
			t.Errorf("IsTextFile(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestH8_StrictManifestSelfHash(t *testing.T) {
	dupHash := Sha256Bytes([]byte("duplicate-collision-probe"))
	rawTemplate := `{
  "schemaVersion": 1,
  "supersedes": %q,
  "files": [
    {
      "path": "01-IDENTITY.md",
      "sha256": %q
    },
    {
      "path": "manifest.json",
      "layer": "manifest",
      "sha256": %q
    }
  ]
}
`
	raw := []byte(fmt.Sprintf(rawTemplate, dupHash, dupHash, dupHash))
	expectedWithManifestZeroed := []byte(fmt.Sprintf(rawTemplate, dupHash, dupHash, DefaultPlaceholder))
	buggyWithSupersedesZeroed := []byte(fmt.Sprintf(rawTemplate, DefaultPlaceholder, dupHash, dupHash))

	got := ComputeManifestSelfHashFromBytes(raw, dupHash, DefaultPlaceholder)
	want := Sha256Bytes(ToLF(expectedWithManifestZeroed))
	buggy := Sha256Bytes(ToLF(buggyWithSupersedesZeroed))

	if got != want {
		t.Fatalf("ComputeManifestSelfHashFromBytes replaced wrong field: got %s, want %s", got, want)
	}
	if got == buggy {
		t.Fatalf("ComputeManifestSelfHashFromBytes matched naive first-occurrence replacement %s", buggy)
	}

	// Verify canonical template manifest (both lowercase and uppercase input hash)
	tplBytes, err := os.ReadFile(filepath.Join("..", "..", "templates", "open-passport-template", "manifest.json"))
	if err != nil {
		t.Fatalf("reading template manifest: %v", err)
	}
	const wantTplHash = "b6d13a7447ba0abb914f54d338c92440acf5ab151615b5ef2260049c7b2fe5af"
	if got := ComputeManifestSelfHashFromBytes(tplBytes, strings.ToUpper(wantTplHash), DefaultPlaceholder); got != wantTplHash {
		t.Fatalf("template self-hash (uppercase input) = %s, want %s", got, wantTplHash)
	}

	// Verify corporate passport manifest if running inside MultiversaGroup monorepo
	corpManifestPath := filepath.Join("..", "..", "..", "multiversaOS", "docs", "passport-context", "manifest.json")
	if corpBytes, err := os.ReadFile(corpManifestPath); err == nil {
		const wantCorpHash = "b823d3137ae5fd348ae3b4c4b066e69d6e7733fd4fd98b5c410706bc1d46f4c7"
		if got := ComputeManifestSelfHashFromBytes(corpBytes, wantCorpHash, DefaultPlaceholder); got != wantCorpHash {
			t.Fatalf("corporate passport self-hash = %s, want %s", got, wantCorpHash)
		}
	}

	// Ambiguity: duplicate manifest.json entry in files must fail closed
	ambiguous := []byte(fmt.Sprintf(`{
  "files": [
    {"path": "manifest.json", "sha256": %q},
    {"path": "manifest.json", "sha256": %q}
  ]
}`, dupHash, dupHash))
	if got := ComputeManifestSelfHashFromBytes(ambiguous, dupHash, DefaultPlaceholder); got != "" {
		t.Fatalf("expected empty hash for duplicate manifest.json entry, got %s", got)
	}

	// Missing manifest.json entry in files must fail closed
	missing := []byte(fmt.Sprintf(`{"files": [{"path": "01-IDENTITY.md", "sha256": %q}]}`, dupHash))
	if got := ComputeManifestSelfHashFromBytes(missing, dupHash, DefaultPlaceholder); got != "" {
		t.Fatalf("expected empty hash when manifest.json entry missing, got %s", got)
	}
}

func TestH8_InvalidHex64Rejected(t *testing.T) {
	valid := strings.Repeat("a", 64)
	if !IsValidHex64(valid) {
		t.Fatalf("expected %q to be valid hex64", valid)
	}

	invalids := []string{
		"",
		strings.Repeat("a", 63),
		strings.Repeat("a", 65),
		strings.Repeat("g", 64),
		strings.Repeat("0", 63) + "-",
	}
	if IsValidHex64(strings.Repeat("A", 64)) {
		t.Errorf("IsValidHex64 accepted uppercase hex")
	}
	for _, s := range invalids {
		if IsValidHex64(s) {
			t.Errorf("IsValidHex64(%q) = true, want false", s)
		}
		if got := ComputeManifestSelfHashFromBytes([]byte(`{"files":[{"path":"manifest.json","sha256":"`+s+`"}]}`), s, DefaultPlaceholder); got != "" {
			t.Errorf("ComputeManifestSelfHashFromBytes accepted invalid hash %q, got %q", s, got)
		}
	}

	// VerifyPassport must fail closed when manifest entry has empty/invalid sha256
	tmpDir := t.TempDir()
	copyDir(t, filepath.Join("..", "..", "templates", "open-passport-template"), tmpDir)
	manifestPath := filepath.Join(tmpDir, "manifest.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("reading manifest: %v", err)
	}
	var m PassportManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshaling manifest: %v", err)
	}
	m.Files[1].Sha256 = "not-a-valid-hex64"
	tampered, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatalf("marshaling tampered manifest: %v", err)
	}
	if err := os.WriteFile(manifestPath, tampered, 0644); err != nil {
		t.Fatalf("writing tampered manifest: %v", err)
	}

	ok, errs, err := VerifyPassport(tmpDir)
	if err != nil {
		t.Fatalf("unexpected error from VerifyPassport: %v", err)
	}
	if ok || len(errs) == 0 {
		t.Fatalf("expected VerifyPassport to fail on invalid hex64 hash, got ok=%v errs=%v", ok, errs)
	}
}

func TestBinaryAssets_BuildAndVerify(t *testing.T) {
	tmpDir := t.TempDir()
	if err := InitPassport(tmpDir, "Binary Passport", "Tester"); err != nil {
		t.Fatalf("InitPassport: %v", err)
	}

	assetsDir := filepath.Join(tmpDir, "assets")
	if err := os.MkdirAll(assetsDir, 0755); err != nil {
		t.Fatalf("mkdir assets: %v", err)
	}

	pngBytes := []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 'I', 'H', 'D', 'R'}
	svgBytes := []byte("<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>\n")
	pdfBytes := []byte("%PDF-1.4\r\n%\xe2\xe3\xcf\xd3\r\n\x00endobj\r\n")

	pngPath := filepath.Join(assetsDir, "diagram.png")
	svgPath := filepath.Join(assetsDir, "logo.svg")
	pdfPath := filepath.Join(assetsDir, "brief.pdf")

	if err := os.WriteFile(pngPath, pngBytes, 0644); err != nil {
		t.Fatalf("write png: %v", err)
	}
	if err := os.WriteFile(svgPath, svgBytes, 0644); err != nil {
		t.Fatalf("write svg: %v", err)
	}
	if err := os.WriteFile(pdfPath, pdfBytes, 0644); err != nil {
		t.Fatalf("write pdf: %v", err)
	}

	m, err := BuildPassport(tmpDir, BuildOptions{
		Name:        "Binary Passport",
		Originator:  "Tester",
		AsOf:        "2026-11-18",
		AutoFixCRLF: true,
	})
	if err != nil {
		t.Fatalf("BuildPassport: %v", err)
	}

	// Binary files must remain byte-for-byte untouched even with AutoFixCRLF: true
	gotPNG, err := os.ReadFile(pngPath)
	if err != nil || !bytes.Equal(gotPNG, pngBytes) {
		t.Fatalf("AutoFixCRLF corrupted PNG bytes: got %x, want %x (err=%v)", gotPNG, pngBytes, err)
	}
	gotPDF, err := os.ReadFile(pdfPath)
	if err != nil || !bytes.Equal(gotPDF, pdfBytes) {
		t.Fatalf("AutoFixCRLF corrupted PDF bytes: got %x, want %x (err=%v)", gotPDF, pdfBytes, err)
	}

	mediaByPath := make(map[string]string, len(m.Files))
	for _, f := range m.Files {
		mediaByPath[f.Path] = f.MediaType
	}
	if mediaByPath["assets/diagram.png"] != "image/png" {
		t.Errorf("png mediaType = %q, want image/png", mediaByPath["assets/diagram.png"])
	}
	if mediaByPath["assets/logo.svg"] != "image/svg+xml" {
		t.Errorf("svg mediaType = %q, want image/svg+xml", mediaByPath["assets/logo.svg"])
	}
	if mediaByPath["assets/brief.pdf"] != "application/pdf" {
		t.Errorf("pdf mediaType = %q, want application/pdf", mediaByPath["assets/brief.pdf"])
	}

	ok, errs, err := VerifyPassport(tmpDir)
	if err != nil {
		t.Fatalf("VerifyPassport error: %v", err)
	}
	if !ok || len(errs) != 0 {
		t.Fatalf("VerifyPassport failed on binary passport: ok=%v errs=%v", ok, errs)
	}
}

func TestVerifyPassport_RejectsCRLFOnMarkdown(t *testing.T) {
	tmpDir := t.TempDir()
	if err := InitPassport(tmpDir, "CRLF Test", "Tester"); err != nil {
		t.Fatalf("InitPassport: %v", err)
	}
	if _, err := BuildPassport(tmpDir, BuildOptions{Name: "CRLF Test", Originator: "Tester", AsOf: "2026-11-18"}); err != nil {
		t.Fatalf("BuildPassport: %v", err)
	}

	if err := os.WriteFile(filepath.Join(tmpDir, "01-IDENTITY.md"), []byte("# 01-IDENTITY.md\r\n\r\nCRLF content\r\n"), 0644); err != nil {
		t.Fatalf("writing CRLF markdown: %v", err)
	}

	ok, errs, err := VerifyPassport(tmpDir)
	if err != nil {
		t.Fatalf("VerifyPassport returned unexpected err: %v", err)
	}
	if ok {
		t.Fatal("expected VerifyPassport to fail on CRLF markdown")
	}
	joined := strings.Join(errs, "\n")
	if !strings.Contains(joined, "CRLF") {
		t.Fatalf("expected CRLF error message, got: %v", errs)
	}
}

func TestConcurrentBuildAndVerifyDeterminism(t *testing.T) {
	setupDir := func(t *testing.T) string {
		t.Helper()
		dir := t.TempDir()
		if err := InitPassport(dir, "Concurrent Passport", "Tester"); err != nil {
			t.Fatalf("InitPassport: %v", err)
		}
		if err := os.MkdirAll(filepath.Join(dir, "extra"), 0755); err != nil {
			t.Fatalf("mkdir extra: %v", err)
		}
		for i := 0; i < 20; i++ {
			md := fmt.Sprintf("# Doc %02d\n\nContent %d\n", i, i)
			if err := os.WriteFile(filepath.Join(dir, "extra", fmt.Sprintf("doc-%02d.md", i)), []byte(md), 0644); err != nil {
				t.Fatalf("write md %d: %v", i, err)
			}
		}
		if err := os.WriteFile(filepath.Join(dir, "extra", "img.png"), []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x00, 0x01}, 0644); err != nil {
			t.Fatalf("write png: %v", err)
		}
		return dir
	}

	opts := BuildOptions{
		Name:       "Concurrent Passport",
		Originator: "Tester",
		AsOf:       "2026-11-18",
	}

	dir1 := setupDir(t)
	dir2 := setupDir(t)

	m1, err := BuildPassport(dir1, opts)
	if err != nil {
		t.Fatalf("BuildPassport dir1: %v", err)
	}
	m2, err := BuildPassport(dir2, opts)
	if err != nil {
		t.Fatalf("BuildPassport dir2: %v", err)
	}

	bytes1, err := os.ReadFile(filepath.Join(dir1, "manifest.json"))
	if err != nil {
		t.Fatalf("read manifest 1: %v", err)
	}
	bytes2, err := os.ReadFile(filepath.Join(dir2, "manifest.json"))
	if err != nil {
		t.Fatalf("read manifest 2: %v", err)
	}
	if !bytes.Equal(bytes1, bytes2) {
		t.Fatalf("concurrent builds produced non-identical manifest.json")
	}
	if !reflect.DeepEqual(m1.Files, m2.Files) {
		t.Fatalf("concurrent builds produced different Files slices")
	}

	for run := 0; run < 5; run++ {
		ok, errs, err := VerifyPassport(dir1)
		if err != nil || !ok || len(errs) != 0 {
			t.Fatalf("run %d VerifyPassport failed: ok=%v errs=%v err=%v", run, ok, errs, err)
		}
	}

	// Tamper two files and verify error ordering is deterministic across runs
	if err := os.WriteFile(filepath.Join(dir1, "01-IDENTITY.md"), []byte("# tampered 1\n"), 0644); err != nil {
		t.Fatalf("tamper 1: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir1, "extra", "doc-05.md"), []byte("# tampered 2\n"), 0644); err != nil {
		t.Fatalf("tamper 2: %v", err)
	}

	var baselineErrs []string
	for run := 0; run < 5; run++ {
		ok, errs, err := VerifyPassport(dir1)
		if err != nil {
			t.Fatalf("run %d VerifyPassport err: %v", run, err)
		}
		if ok || len(errs) != 2 {
			t.Fatalf("run %d expected 2 errors, got ok=%v errs=%v", run, ok, errs)
		}
		if run == 0 {
			baselineErrs = errs
		} else if !reflect.DeepEqual(baselineErrs, errs) {
			t.Fatalf("non-deterministic VerifyPassport error order: run0=%v, run%d=%v", baselineErrs, run, errs)
		}
	}
}

func TestCheckUpdateAndVerifySHA256Sums(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
  "tag_name": "v1.0.1",
  "assets": [
    {
      "name": "SHA256SUMS",
      "browser_download_url": "https://example.com/SHA256SUMS"
    }
  ]
}`))
	}))
	defer srv.Close()

	rep, err := CheckUpdate(context.Background(), "v1.0.0", srv.URL)
	if err != nil {
		t.Fatalf("CheckUpdate failed: %v", err)
	}
	if !rep.UpdateNeeded || rep.LatestVersion != "v1.0.1" || !rep.HasSHA256Sums {
		t.Fatalf("unexpected UpdateReport: %+v", rep)
	}

	fakeBin := []byte("openpassport-test-binary-payload\n")
	wantHash := Sha256Bytes(fakeBin)
	sums := fmt.Sprintf("%s  dist/openpassport-linux-amd64\n", wantHash)

	gotHash, err := VerifyBinaryAgainstSHA256Sums(fakeBin, "openpassport-linux-amd64", sums)
	if err != nil || gotHash != wantHash {
		t.Fatalf("VerifyBinaryAgainstSHA256Sums failed: got=%s err=%v", gotHash, err)
	}

	if _, err := VerifyBinaryAgainstSHA256Sums([]byte("tampered"), "openpassport-linux-amd64", sums); err == nil {
		t.Fatal("expected tampered binary to fail SHA256SUMS verification")
	}
}
