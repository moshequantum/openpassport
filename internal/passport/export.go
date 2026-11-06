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
	"time"
)

// ExportProfile exports a verified, authenticated context profile into a deterministic .tar.gz bundle.
func ExportProfile(dir, profileID, outFile string) error {
	// Gate B2: Verify passport integrity before packing
	valid, errs, err := VerifyPassport(dir)
	if err != nil {
		return fmt.Errorf("pre-export verification failed: %w", err)
	}
	if !valid {
		return fmt.Errorf("pre-export verification failed with %d error(s): %v", len(errs), errs)
	}

	manifestPath := filepath.Join(dir, "manifest.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("reading manifest.json: %w", err)
	}

	var m PassportManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("parsing manifest.json: %w", err)
	}

	var matchedProfile *PassportProfile
	for _, p := range m.Profiles {
		if p.ID == profileID {
			matchedProfile = &p
			break
		}
	}
	if matchedProfile == nil {
		return fmt.Errorf("perfil %q no encontrado en manifest.json", profileID)
	}

	// Build set of files to include, starting with bootstrap
	allowedMap := make(map[string]bool)
	allowedMap["manifest.json"] = true
	allowedMap["MASTER-PROMPT.md"] = true
	for _, f := range matchedProfile.Files {
		allowedMap[f] = true
	}

	var sortedPaths []string
	for relPath := range allowedMap {
		sortedPaths = append(sortedPaths, filepath.ToSlash(relPath))
	}
	// Deterministic sorting by raw byte order
	sort.Strings(sortedPaths)

	out, err := os.Create(outFile)
	if err != nil {
		return fmt.Errorf("creating export archive: %w", err)
	}
	defer out.Close()

	gw := gzip.NewWriter(out)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	for _, relPath := range sortedPaths {
		// Gate B1: Prevent path traversal
		fullPath, err := SafeJoin(dir, relPath)
		if err != nil {
			return fmt.Errorf("security violation in exported file path %q: %w", relPath, err)
		}

		info, err := os.Stat(fullPath)
		if err != nil {
			return fmt.Errorf("stat failed on %q: %w", relPath, err)
		}

		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return fmt.Errorf("tar header creation failed on %q: %w", relPath, err)
		}

		// Gate H4: Deterministic header metadata
		header.Name = relPath
		header.ModTime = time.Unix(0, 0).UTC()
		header.Uid = 0
		header.Gid = 0
		header.Uname = ""
		header.Gname = ""
		header.Mode = 0644
		header.Format = tar.FormatPAX

		if err := tw.WriteHeader(header); err != nil {
			return fmt.Errorf("writing tar header for %q: %w", relPath, err)
		}

		f, err := os.Open(fullPath)
		if err != nil {
			return fmt.Errorf("opening %q: %w", relPath, err)
		}

		if _, err := io.Copy(tw, f); err != nil {
			f.Close()
			return fmt.Errorf("copying %q into tar: %w", relPath, err)
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("closing %q: %w", relPath, err)
		}
	}

	if err := tw.Close(); err != nil {
		return fmt.Errorf("closing tar writer: %w", err)
	}
	if err := gw.Close(); err != nil {
		return fmt.Errorf("closing gzip writer: %w", err)
	}

	return nil
}
