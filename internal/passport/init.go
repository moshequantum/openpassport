package passport

import (
	"fmt"
	"os"
	"path/filepath"
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
