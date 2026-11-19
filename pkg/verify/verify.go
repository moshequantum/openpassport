package verify

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

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

type entryVerifyResult struct {
	verifiedPath string
	errs         []string
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
	manifestCount := 0
	for i := range m.Files {
		if m.Files[i].Path == "manifest.json" {
			manifestCount++
			if manifestEntry == nil {
				manifestEntry = &m.Files[i]
			}
		}
	}
	if manifestEntry == nil {
		return nil, fmt.Errorf("manifest validation failed: manifest.json entry missing from files list")
	}
	if manifestCount != 1 {
		return nil, fmt.Errorf("manifest validation failed: duplicate manifest.json entry in files list")
	}

	curHash := strings.ToLower(manifestEntry.Sha256)
	rep := &Report{
		Manifest:         &m,
		ExpectedSelfHash: curHash,
		VerifiedFiles:    make([]string, 0, len(m.Files)),
	}

	if !passport.IsValidHex64(curHash) {
		errMsg := fmt.Sprintf("invalid sha256 format for manifest.json: %q", manifestEntry.Sha256)
		rep.Errors = append(rep.Errors, errMsg)
		return rep, fmt.Errorf("%s", errMsg)
	}

	computedSelfHash := passport.ComputeManifestSelfHashFromBytes(rawBytes, manifestEntry.Sha256, placeholder)
	rep.ComputedSelfHash = computedSelfHash

	if computedSelfHash != curHash {
		errMsg := fmt.Sprintf("cryptographic seal mismatch for manifest: expected %s, computed %s", curHash, computedSelfHash)
		rep.Errors = append(rep.Errors, errMsg)
		return rep, fmt.Errorf("%s", errMsg)
	}

	rep.VerifiedFiles = append(rep.VerifiedFiles, "manifest.json")

	jobIndices := make([]int, 0, len(m.Files))
	for i, f := range m.Files {
		if f.Path == "manifest.json" {
			continue
		}
		jobIndices = append(jobIndices, i)
	}

	results := make([]entryVerifyResult, len(m.Files))
	if len(jobIndices) > 0 {
		jobs := make(chan int, len(jobIndices))
		for _, idx := range jobIndices {
			jobs <- idx
		}
		close(jobs)

		workers := runtime.GOMAXPROCS(0)
		if workers < 1 {
			workers = 1
		}
		if len(jobIndices) < workers {
			workers = len(jobIndices)
		}

		var wg sync.WaitGroup
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for idx := range jobs {
					results[idx] = verifyFileEntry(baseDir, m.Files[idx])
				}
			}()
		}
		wg.Wait()
	}

	for _, idx := range jobIndices {
		res := results[idx]
		if len(res.errs) > 0 {
			rep.Errors = append(rep.Errors, res.errs...)
		} else if res.verifiedPath != "" {
			rep.VerifiedFiles = append(rep.VerifiedFiles, res.verifiedPath)
		}
	}

	if len(rep.Errors) > 0 {
		rep.Valid = false
		return rep, fmt.Errorf("%s", rep.Errors[0])
	}

	rep.Valid = true
	return rep, nil
}

func verifyFileEntry(baseDir string, f passport.PassportFileEntry) entryVerifyResult {
	filePath, err := passport.SafeJoin(baseDir, f.Path)
	if err != nil {
		return entryVerifyResult{
			errs: []string{fmt.Sprintf("file %q security violation: %v", f.Path, err)},
		}
	}

	expectedHash := strings.ToLower(f.Sha256)
	if !passport.IsValidHex64(expectedHash) {
		return entryVerifyResult{
			errs: []string{fmt.Sprintf("file %q has invalid sha256 format: %q", f.Path, f.Sha256)},
		}
	}

	content, err := os.ReadFile(filePath)
	if err != nil {
		return entryVerifyResult{
			errs: []string{fmt.Sprintf("file %q: reading file: %v", f.Path, err)},
		}
	}

	var entryErrs []string
	if passport.IsTextFile(f.Path) && passport.HasCRLF(content) {
		entryErrs = append(entryErrs, fmt.Sprintf("file %q violates LF contract: CRLF detected", f.Path))
	}

	computedHash := passport.Sha256Bytes(content)
	if computedHash != expectedHash {
		entryErrs = append(entryErrs, fmt.Sprintf("file %q integrity check failed: expected %s, got %s", f.Path, expectedHash, computedHash))
	}

	if len(entryErrs) > 0 {
		return entryVerifyResult{errs: entryErrs}
	}
	return entryVerifyResult{verifiedPath: f.Path}
}
