package passport

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
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
		return false, []string{"manifest.json no listado dentro de files."}, nil
	}
	if manifestCount != 1 {
		return false, []string{"Múltiples entradas manifest.json detectadas en files."}, nil
	}

	placeholder := m.ManifestSelfHash.Placeholder
	if placeholder == "" {
		placeholder = DefaultPlaceholder
	}
	manifestHash := strings.ToLower(manifestEntry.Sha256)
	if !IsValidHex64(manifestHash) {
		errs = append(errs, fmt.Sprintf("Hash sha256 inválido para manifest.json: %q", manifestEntry.Sha256))
	} else {
		computedSelfHash := ComputeManifestSelfHashFromBytes(data, manifestEntry.Sha256, placeholder)
		if manifestHash != computedSelfHash {
			errs = append(errs, fmt.Sprintf("Discrepancia en manifestSelfHash: manifest=%s, computado=%s", manifestEntry.Sha256, computedSelfHash))
		}
	}

	jobIndices := make([]int, 0, len(m.Files))
	for i, f := range m.Files {
		if f.Path == "manifest.json" {
			continue
		}
		jobIndices = append(jobIndices, i)
	}

	results := make([][]string, len(m.Files))
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
					results[idx] = verifyPassportEntry(dir, m.Files[idx])
				}
			}()
		}
		wg.Wait()
	}

	for _, entryErrs := range results {
		errs = append(errs, entryErrs...)
	}

	return len(errs) == 0, errs, nil
}

func verifyPassportEntry(dir string, f PassportFileEntry) []string {
	var entryErrs []string

	// Security gate: SafeJoin prevents traversal out of passport directory
	p, err := SafeJoin(dir, f.Path)
	if err != nil {
		entryErrs = append(entryErrs, fmt.Sprintf("Violación de seguridad en ruta %q: %v", f.Path, err))
		return entryErrs
	}

	expectedHash := strings.ToLower(f.Sha256)
	if !IsValidHex64(expectedHash) {
		entryErrs = append(entryErrs, fmt.Sprintf("Hash sha256 inválido en manifest para %s: %q", f.Path, f.Sha256))
		return entryErrs
	}

	fdata, err := os.ReadFile(p)
	if err != nil {
		entryErrs = append(entryErrs, fmt.Sprintf("Archivo faltante en disco: %s", f.Path))
		return entryErrs
	}

	if IsTextFile(f.Path) && HasCRLF(fdata) {
		entryErrs = append(entryErrs, fmt.Sprintf("CRLF detectado en %s (viola contrato LF)", f.Path))
	}

	h := Sha256Bytes(fdata)
	if h != expectedHash {
		entryErrs = append(entryErrs, fmt.Sprintf("Hash inválido para %s: esperado=%s, obtenido=%s", f.Path, expectedHash, h))
	}

	return entryErrs
}
