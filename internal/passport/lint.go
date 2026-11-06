package passport

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LintPassport performs static linting on an OpenPassport directory.
func LintPassport(dir string) ([]string, error) {
	var issues []string

	// 1. Check .gitattributes
	if _, err := os.Stat(filepath.Join(dir, ".gitattributes")); os.IsNotExist(err) {
		issues = append(issues, "Falta .gitattributes (obligatorio para evitar corrupción CRLF en Windows).")
	}

	// 2. Check 7 canonical layers
	for _, layer := range CanonicalLayers {
		if _, err := os.Stat(filepath.Join(dir, layer)); os.IsNotExist(err) {
			issues = append(issues, fmt.Sprintf("Capa obligatoria ausente: %s", layer))
		}
	}

	// 3. If manifest.json exists, check consistency against disk (M4)
	manifestPath := filepath.Join(dir, "manifest.json")
	if mData, err := os.ReadFile(manifestPath); err == nil {
		var m PassportManifest
		if err := json.Unmarshal(mData, &m); err == nil {
			for _, f := range m.Files {
				if f.Path == "manifest.json" {
					continue
				}
				targetPath, err := SafeJoin(dir, f.Path)
				if err != nil {
					issues = append(issues, fmt.Sprintf("Manifest referencia ruta con violación de seguridad: %s", f.Path))
					continue
				}
				if _, err := os.Stat(targetPath); os.IsNotExist(err) {
					issues = append(issues, fmt.Sprintf("Manifest referencia archivo inexistente en disco: %s", f.Path))
				}
			}
		}
	}

	// 4. Scan files for CRLF or lone CR (skipping .git and node_modules)
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

		ext := strings.ToLower(filepath.Ext(p))
		if ext == ".md" || ext == ".json" || ext == ".txt" {
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			if HasCRLF(data) {
				rel, _ := filepath.Rel(dir, p)
				if bytes.Contains(data, []byte("\r\n")) {
					issues = append(issues, fmt.Sprintf("CRLF (\\r\\n) detectado en %s (debe normalizarse a LF puro).", rel))
				} else {
					issues = append(issues, fmt.Sprintf("CR aislado (\\r) detectado en %s (debe normalizarse a LF puro).", rel))
				}
			}
		}
		return nil
	})

	return issues, err
}
