package verify

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/moshequantum/openpassport/internal/passport"
)

// Report holds the result of verifying an OpenPassport package.
type Report struct {
	Valid            bool                       `json:"valid"`
	Manifest         *passport.PassportManifest `json:"manifest,omitempty"`
	ComputedSelfHash string                     `json:"computedSelfHash"`
	ExpectedSelfHash string                     `json:"expectedSelfHash"`
	VerifiedFiles    []string                   `json:"verifiedFiles"`
	Errors           []string                   `json:"errors,omitempty"`
}

// Verify audits a passport directory or manifest.json file against the OpenPassport v1 contract (C1).
func Verify(dirOrManifestPath string) (*Report, error) {
	fi, err := os.Stat(dirOrManifestPath)
	if err != nil {
		return nil, fmt.Errorf("reading path: %w", err)
	}

	var manifestPath, baseDir string
	if fi.IsDir() {
		manifestPath = filepath.Join(dirOrManifestPath, "manifest.json")
		baseDir = dirOrManifestPath
	} else {
		manifestPath = dirOrManifestPath
		baseDir = filepath.Dir(dirOrManifestPath)
	}

	rawBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("reading manifest.json: %w", err)
	}

	var m passport.PassportManifest
	if err := json.Unmarshal(rawBytes, &m); err != nil {
		return nil, fmt.Errorf("parsing manifest.json: %w", err)
	}

	if m.Name == "" {
		return nil, fmt.Errorf("manifest validation failed: missing 'name'")
	}
	if m.PackageVersion == "" {
		return nil, fmt.Errorf("manifest validation failed: missing 'packageVersion'")
	}
	if len(m.Files) == 0 {
		return nil, fmt.Errorf("manifest validation failed: 'files' list is empty")
	}

	placeholder := m.ManifestSelfHash.Placeholder
	if placeholder == "" {
		placeholder = passport.DefaultPlaceholder
	}

	var manifestEntry *passport.PassportFileEntry
	for i := range m.Files {
		if m.Files[i].Path == "manifest.json" {
			manifestEntry = &m.Files[i]
			break
		}
	}
	if manifestEntry == nil {
		return nil, fmt.Errorf("manifest validation failed: manifest.json entry missing from files list")
	}

	curHash := strings.ToLower(manifestEntry.Sha256)
	computedSelfHash := passport.ComputeManifestSelfHashFromBytes(rawBytes, curHash, placeholder)

	rep := &Report{
		Manifest:         &m,
		ExpectedSelfHash: curHash,
		ComputedSelfHash: computedSelfHash,
		VerifiedFiles:    make([]string, 0, len(m.Files)),
	}

	if computedSelfHash != curHash {
		rep.Errors = append(rep.Errors, fmt.Sprintf("cryptographic seal mismatch for manifest: expected %s, computed %s", curHash, computedSelfHash))
		return rep, fmt.Errorf("%s", rep.Errors[0])
	}

	rep.VerifiedFiles = append(rep.VerifiedFiles, "manifest.json")

	for _, f := range m.Files {
		if f.Path == "manifest.json" {
			continue
		}
		filePath := filepath.Join(baseDir, filepath.FromSlash(f.Path))
		content, err := os.ReadFile(filePath)
		if err != nil {
			rep.Errors = append(rep.Errors, fmt.Sprintf("file %q: reading file: %v", f.Path, err))
			return rep, fmt.Errorf("file %q: reading file: %w", f.Path, err)
		}

		computedHash := passport.Sha256Bytes(passport.ToLF(content))
		expectedHash := strings.ToLower(f.Sha256)
		if computedHash != expectedHash {
			errMsg := fmt.Sprintf("file %q integrity check failed: expected %s, got %s", f.Path, expectedHash, computedHash)
			rep.Errors = append(rep.Errors, errMsg)
			return rep, fmt.Errorf("%s", errMsg)
		}

		rep.VerifiedFiles = append(rep.VerifiedFiles, f.Path)
	}

	rep.Valid = true
	return rep, nil
}
