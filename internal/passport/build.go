package passport

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// BuildOptions contains optional parameters for building a passport.
type BuildOptions struct {
	Name               string
	Originator         string
	TechnicalAuthority string
	AsOf               string
	AutoFixCRLF        bool
}

// BuildPassport builds the deterministic manifest and generation receipt for an OpenPassport directory.
func BuildPassport(dir string, opts BuildOptions) (*PassportManifest, error) {
	manifestPath := filepath.Join(dir, "manifest.json")

	// Determine asOf date
	asOf := opts.AsOf
	if asOf == "" {
		// Attempt to preserve existing manifest asOf date for reproducibility
		if existingData, err := os.ReadFile(manifestPath); err == nil {
			var oldM PassportManifest
			if err := json.Unmarshal(existingData, &oldM); err == nil && oldM.AsOf != "" {
				asOf = oldM.AsOf
			}
		}
	}
	if asOf == "" {
		asOf = time.Now().UTC().Format("2006-01-02")
	}

	techAuthority := opts.TechnicalAuthority
	if techAuthority == "" {
		if existingData, err := os.ReadFile(manifestPath); err == nil {
			var oldM PassportManifest
			if err := json.Unmarshal(existingData, &oldM); err == nil && oldM.TechnicalAuthority != "" {
				techAuthority = oldM.TechnicalAuthority
			}
		}
	}
	if techAuthority == "" {
		techAuthority = "Founding AI Product Engineer / Design Engineer"
	}

	// Ensure .gitattributes exists
	gaPath := filepath.Join(dir, ".gitattributes")
	if _, err := os.Stat(gaPath); os.IsNotExist(err) {
		if err := os.WriteFile(gaPath, []byte(CanonicalGitattributes), 0644); err != nil {
			return nil, fmt.Errorf("writing .gitattributes: %w", err)
		}
	}

	fileEntries := make([]PassportFileEntry, 0)

	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			baseName := info.Name()
			if baseName == ".git" || baseName == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}

		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)

		// Exclusions:
		// .git/ already skipped. Ignore manifest.json, generation.receipt.json, *.tar.gz, .git* EXCEPT .gitattributes
		if rel == "manifest.json" || rel == "generation.receipt.json" || strings.HasSuffix(rel, ".tar.gz") {
			return nil
		}
		if strings.HasPrefix(rel, ".git") && rel != ".gitattributes" {
			return nil
		}

		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}

		ext := strings.ToLower(filepath.Ext(p))
		if opts.AutoFixCRLF && (ext == ".md" || ext == ".json" || ext == ".txt") && HasCRLF(data) {
			data = ToLF(data)
			if err := os.WriteFile(p, data, 0644); err != nil {
				return fmt.Errorf("autofixing CRLF on %q: %w", p, err)
			}
		}

		hash := Sha256Bytes(data)
		if len(hash) != 64 {
			return fmt.Errorf("invalid hash generated for %q", rel)
		}

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
		return nil, fmt.Errorf("walking passport directory: %w", err)
	}

	// Canonical byte order sort
	sort.Slice(fileEntries, func(i, j int) bool {
		return fileEntries[i].Path < fileEntries[j].Path
	})

	name := opts.Name
	if name == "" {
		name = "Pasaporte de Contexto"
	}
	originator := opts.Originator
	if originator == "" {
		originator = "Originador"
	}

	manifest := PassportManifest{
		SchemaVersion:      1,
		Kind:               "PASSPORT-CONTEXT",
		Name:               name,
		PackageVersion:     "1.0.0",
		Originator:         originator,
		TechnicalAuthority: techAuthority,
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
		return nil, fmt.Errorf("encoding initial manifest: %w", err)
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
		return nil, fmt.Errorf("encoding final manifest: %w", err)
	}
	finalData := ToLF([]byte(finalBuf.String()))

	if err := os.WriteFile(manifestPath, finalData, 0644); err != nil {
		return nil, fmt.Errorf("writing manifest.json: %w", err)
	}

	// Write generation.receipt.json
	receiptFiles := make([]ReceiptFileEntry, 0, len(manifest.Files))
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
	if err := renc.Encode(receipt); err != nil {
		return nil, fmt.Errorf("encoding receipt: %w", err)
	}

	receiptPath := filepath.Join(dir, "generation.receipt.json")
	if err := os.WriteFile(receiptPath, ToLF([]byte(receiptBuf.String())), 0644); err != nil {
		return nil, fmt.Errorf("writing generation.receipt.json: %w", err)
	}

	return &manifest, nil
}

func extractPaths(files []PassportFileEntry, layers ...string) []string {
	lmap := make(map[string]bool)
	for _, l := range layers {
		lmap[l] = true
	}
	res := make([]string, 0)
	for _, f := range files {
		if lmap[f.Layer] && f.Visibility == "public" {
			res = append(res, f.Path)
		}
	}
	return res
}

func allPaths(files []PassportFileEntry) []string {
	res := make([]string, 0, len(files))
	for _, f := range files {
		res = append(res, f.Path)
	}
	return res
}
