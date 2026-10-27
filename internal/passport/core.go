package passport

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var CanonicalLayers = []string{
	"01-IDENTITY.md",
	"02-DOCTRINE.md",
	"03-VOICE.md",
	"04-OFFER.md",
	"05-GOVERNANCE.md",
	"06-CURRENT-STATE.md",
	"07-EVIDENCE.md",
}

var CanonicalGitattributes = `* text=auto eol=lf
*.md text eol=lf
*.json text eol=lf
`

func InitPassport(dir, name, originator string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Write .gitattributes
	if err := os.WriteFile(filepath.Join(dir, ".gitattributes"), []byte(CanonicalGitattributes), 0644); err != nil {
		return err
	}

	// Scaffold 7 layers if not present
	for _, layer := range CanonicalLayers {
		p := filepath.Join(dir, layer)
		if _, err := os.Stat(p); os.IsNotExist(err) {
			content := fmt.Sprintf("# %s\n\n> Documento canónico del estándar OpenPassport v1.0 para %s.\n", layer, name)
			if err := os.WriteFile(p, []byte(content), 0644); err != nil {
				return err
			}
		}
	}

	// Scaffold MASTER-PROMPT.md
	mpPath := filepath.Join(dir, "MASTER-PROMPT.md")
	if _, err := os.Stat(mpPath); os.IsNotExist(err) {
		mpContent := fmt.Sprintf(`# MASTER PROMPT — Intérprete Canónico de Inteligencia Artificial

Eres el Copiloto Oficial y Guardián de Contexto de **%s**.

## 1. Jerarquía Estricta de Precedencia (Invariante Dura)

$$\text{Instrucción del Titular} > \text{Gobernanza (05)} > \text{Identidad y Doctrina (01, 02)} > \text{Oferta Comercial (04)} > \text{Voz de Marca (03)} > \text{Evidencia Epistémica (07)} > \text{Estado Temporal (06)} > \text{Conocimiento General}$$
`, name)
		if err := os.WriteFile(mpPath, []byte(mpContent), 0644); err != nil {
			return err
		}
	}

	// Scaffold README.md
	rmPath := filepath.Join(dir, "README.md")
	if _, err := os.Stat(rmPath); os.IsNotExist(err) {
		rmContent := fmt.Sprintf("# %s — Pasaporte de Contexto (OpenPassport v1.0)\n\nOriginador: %s\n", name, originator)
		if err := os.WriteFile(rmPath, []byte(rmContent), 0644); err != nil {
			return err
		}
	}

	return nil
}

func LintPassport(dir string) ([]string, error) {
	var issues []string

	// 1. Check .gitattributes
	if _, err := os.Stat(filepath.Join(dir, ".gitattributes")); os.IsNotExist(err) {
		issues = append(issues, "Falta .gitattributes (obligatorio para evitar corrupción CRLF en Windows).")
	}

	// 2. Check 7 layers
	for _, layer := range CanonicalLayers {
		if _, err := os.Stat(filepath.Join(dir, layer)); os.IsNotExist(err) {
			issues = append(issues, fmt.Sprintf("Capa obligatoria ausente: %s", layer))
		}
	}

	// 3. Scan files for CRLF
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		ext := strings.ToLower(filepath.Ext(p))
		if ext == ".md" || ext == ".json" || ext == ".txt" {
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			if HasCRLF(data) {
				rel, _ := filepath.Rel(dir, p)
				issues = append(issues, fmt.Sprintf("CRLF detectado en %s (debe normalizarse a LF puro).", rel))
			}
		}
		return nil
	})

	return issues, err
}

func BuildPassport(dir, name, originator string, autoFixCRLF bool) (*PassportManifest, error) {
	asOf := time.Now().Format("2006-01-02")

	// Ensure .gitattributes exists
	gaPath := filepath.Join(dir, ".gitattributes")
	if _, err := os.Stat(gaPath); os.IsNotExist(err) {
		if err := os.WriteFile(gaPath, []byte(CanonicalGitattributes), 0644); err != nil {
			return nil, err
		}
	}

	var fileEntries []PassportFileEntry

	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "manifest.json" || rel == "generation.receipt.json" || strings.HasPrefix(rel, ".git") {
			return nil
		}

		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}

		ext := strings.ToLower(filepath.Ext(p))
		if autoFixCRLF && (ext == ".md" || ext == ".json" || ext == ".txt") && HasCRLF(data) {
			data = ToLF(data)
			if err := os.WriteFile(p, data, 0644); err != nil {
				return err
			}
		}

		hash := Sha256Bytes(data)
		layer := "custom"
		base := filepath.Base(rel)
		switch {
		case strings.HasPrefix(base, "01-IDENTITY"):
			layer = "identity"
		case strings.HasPrefix(base, "02-DOCTRINE"):
			layer = "doctrine"
		case strings.HasPrefix(base, "03-VOICE"):
			layer = "voice"
		case strings.HasPrefix(base, "04-OFFER"):
			layer = "offer"
		case strings.HasPrefix(base, "05-GOVERNANCE"):
			layer = "governance"
		case strings.HasPrefix(base, "06-CURRENT-STATE"):
			layer = "state"
		case strings.HasPrefix(base, "07-EVIDENCE"):
			layer = "evidence"
		case base == "MASTER-PROMPT.md":
			layer = "interpreter"
		case base == "README.md":
			layer = "guide"
		case base == ".gitattributes":
			layer = "config"
		}

		mediaType := "text/plain"
		if ext == ".md" {
			mediaType = "text/markdown"
		} else if ext == ".json" {
			mediaType = "application/json"
		}

		vis := "public"
		if strings.HasPrefix(rel, "private") {
			vis = "private"
		}

		fileEntries = append(fileEntries, PassportFileEntry{
			Path:       rel,
			Layer:      layer,
			MediaType:  mediaType,
			Sha256:     hash,
			Visibility: vis,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Slice(fileEntries, func(i, j int) bool {
		return fileEntries[i].Path < fileEntries[j].Path
	})

	manifest := PassportManifest{
		SchemaVersion:      1,
		Kind:               "PASSPORT-CONTEXT",
		Name:               name,
		PackageVersion:     "1.0.0",
		Originator:         originator,
		TechnicalAuthority: "Founding AI Product Engineer / Design Engineer",
		Language:           "es",
		AsOf:               asOf,
		UpdatedAt:          asOf,
		Ownership:          "originator-owned",
		HashAlgorithm:      "sha256",
		HashEncoding:       "lowercase-hex",
		HashByteContract:   "UTF-8, LF line endings",
		ManifestSelfHash: ManifestSelfHashConfig{
			HashMode:    "raw-bytes-with-own-sha256-replaced-by-64-zeroes",
			Path:        "manifest.json",
			Placeholder: DefaultPlaceholder,
		},
		LoadContract: LoadContract{
			Bootstrap:         []string{"manifest.json"},
			FirstContext:      "MASTER-PROMPT.md",
			Then:              "profiles[].files in listed order",
			DuplicatesAllowed: false,
		},
		TemporalInvariant: &TemporalInvariant{AsOf: asOf},
		Files: append([]PassportFileEntry{
			{
				Path:       "manifest.json",
				Layer:      "manifest",
				MediaType:  "application/json",
				Sha256:     DefaultPlaceholder,
				Visibility: "public",
			},
		}, fileEntries...),
		Profiles: []PassportProfile{
			{
				ID:          "core-public",
				Description: "Public identity, doctrine, and voice guidelines",
				Files:       extractPaths(fileEntries, "identity", "doctrine", "voice", "interpreter", "guide"),
			},
			{
				ID:          "full",
				Description: "Complete canonical passport package",
				Files:       allPaths(fileEntries),
			},
		},
	}

	// First encode with 64 zeroes placeholder
	initialBuf := new(strings.Builder)
	enc := json.NewEncoder(initialBuf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(manifest); err != nil {
		return nil, err
	}
	initialBytes := ToLF([]byte(initialBuf.String()))
	selfHash := Sha256Bytes(initialBytes)

	// Update self-hash entry
	manifest.Files[0].Sha256 = selfHash

	// Re-encode final manifest
	finalBuf := new(strings.Builder)
	fenc := json.NewEncoder(finalBuf)
	fenc.SetIndent("", "  ")
	fenc.SetEscapeHTML(false)
	if err := fenc.Encode(manifest); err != nil {
		return nil, err
	}
	finalData := ToLF([]byte(finalBuf.String()))

	manifestPath := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(manifestPath, finalData, 0644); err != nil {
		return nil, err
	}

	// Write generation.receipt.json
	var receiptFiles []ReceiptFileEntry
	for _, f := range manifest.Files {
		receiptFiles = append(receiptFiles, ReceiptFileEntry{
			Path:   f.Path,
			Layer:  f.Layer,
			Sha256: f.Sha256,
		})
	}

	receipt := PassportReceipt{
		SchemaVersion: 1,
		Kind:          "passport-context-generation-receipt",
		Status:        "pass",
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		AsOf:          asOf,
		Passport: PassportReceiptInfo{
			Name:               manifest.Name,
			PackageVersion:     manifest.PackageVersion,
			Originator:         manifest.Originator,
			TechnicalAuthority: manifest.TechnicalAuthority,
			ManifestSha256:     selfHash,
			FileCount:          len(manifest.Files),
			Files:              receiptFiles,
		},
	}

	receiptBuf := new(strings.Builder)
	renc := json.NewEncoder(receiptBuf)
	renc.SetIndent("", "  ")
	renc.SetEscapeHTML(false)
	_ = renc.Encode(receipt)

	receiptPath := filepath.Join(dir, "generation.receipt.json")
	_ = os.WriteFile(receiptPath, ToLF([]byte(receiptBuf.String())), 0644)

	return &manifest, nil
}

func VerifyPassport(dir string) (bool, []string, error) {
	var errs []string

	manifestPath := filepath.Join(dir, "manifest.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return false, []string{"manifest.json no encontrado."}, err
	}

	var m PassportManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return false, []string{"Error parseando manifest.json: " + err.Error()}, err
	}

	var manifestEntry *PassportFileEntry
	for i := range m.Files {
		if m.Files[i].Path == "manifest.json" {
			manifestEntry = &m.Files[i]
			break
		}
	}
	if manifestEntry == nil {
		return false, []string{"manifest.json no listado dentro de files."}, nil
	}

	placeholder := m.ManifestSelfHash.Placeholder
	if placeholder == "" {
		placeholder = DefaultPlaceholder
	}
	computedSelfHash := ComputeManifestSelfHashFromBytes(data, manifestEntry.Sha256, placeholder)

	if manifestEntry.Sha256 != computedSelfHash {
		errs = append(errs, fmt.Sprintf("Discrepancia en manifestSelfHash: manifest=%s, computado=%s", manifestEntry.Sha256, computedSelfHash))
	}

	// Verify each file
	for _, f := range m.Files {
		if f.Path == "manifest.json" {
			continue
		}
		p := filepath.Join(dir, f.Path)
		fdata, err := os.ReadFile(p)
		if err != nil {
			errs = append(errs, fmt.Sprintf("Archivo faltante en disco: %s", f.Path))
			continue
		}
		ext := strings.ToLower(filepath.Ext(p))
		if (ext == ".md" || ext == ".json" || ext == ".txt") && HasCRLF(fdata) {
			errs = append(errs, fmt.Sprintf("CRLF detectado en %s (viola contrato LF)", f.Path))
		}
		h := Sha256Bytes(fdata)
		if h != f.Sha256 {
			errs = append(errs, fmt.Sprintf("Hash inválido para %s: esperado=%s, obtenido=%s", f.Path, f.Sha256, h))
		}
	}

	return len(errs) == 0, errs, nil
}

func ExportProfile(dir, profileID, outFile string) error {
	manifestPath := filepath.Join(dir, "manifest.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}

	var m PassportManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}

	var matchedProfile *PassportProfile
	for _, p := range m.Profiles {
		if p.ID == profileID {
			matchedProfile = &p
			break
		}
	}
	if matchedProfile == nil {
		return fmt.Errorf("perfil '%s' no encontrado en manifest.json", profileID)
	}

	allowed := make(map[string]bool)
	allowed["manifest.json"] = true
	allowed["MASTER-PROMPT.md"] = true
	for _, f := range matchedProfile.Files {
		allowed[f] = true
	}

	out, err := os.Create(outFile)
	if err != nil {
		return err
	}
	defer out.Close()

	gw := gzip.NewWriter(out)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()

	for relPath := range allowed {
		fullPath := filepath.Join(dir, relPath)
		info, err := os.Stat(fullPath)
		if err != nil {
			continue
		}
		header, err := tar.FileInfoHeader(info, info.Name())
		if err != nil {
			continue
		}
		header.Name = relPath

		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		f, err := os.Open(fullPath)
		if err != nil {
			continue
		}
		_, _ = io.Copy(tw, f)
		f.Close()
	}

	return nil
}

func extractPaths(files []PassportFileEntry, layers ...string) []string {
	lmap := make(map[string]bool)
	for _, l := range layers {
		lmap[l] = true
	}
	var res []string
	for _, f := range files {
		if lmap[f.Layer] && f.Visibility == "public" {
			res = append(res, f.Path)
		}
	}
	return res
}

func allPaths(files []PassportFileEntry) []string {
	var res []string
	for _, f := range files {
		res = append(res, f.Path)
	}
	return res
}
