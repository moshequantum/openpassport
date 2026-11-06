package passport

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// VerifyPassport performs cryptographic and structural verification of a passport directory.
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

		// Security gate: SafeJoin prevents traversal out of passport directory
		p, err := SafeJoin(dir, f.Path)
		if err != nil {
			errs = append(errs, fmt.Sprintf("Violación de seguridad en ruta %q: %v", f.Path, err))
			continue
		}

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
