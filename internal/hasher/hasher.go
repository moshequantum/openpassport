package hasher

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/moshequantum/openpassport/pkg/schema"
)

const ZeroHash64 = "0000000000000000000000000000000000000000000000000000000000000000"

// HashContent calculates the SHA-256 of content after normalizing line endings to LF (\n).
func HashContent(content []byte) string {
	// Normalize CRLF to LF
	normalized := bytes.ReplaceAll(content, []byte("\r\n"), []byte("\n"))
	sum := sha256.Sum256(normalized)
	return hex.EncodeToString(sum[:])
}

// SealManifest calculates the self-sealing SHA-256 of the manifest.
// It places 64 zeros in the SHA256 field, serializes to deterministic JSON, and computes the hash.
func SealManifest(m *schema.Manifest) (string, error) {
	clone := *m
	clone.SHA256 = ZeroHash64

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(clone); err != nil {
		return "", err
	}

	// Normalize trailing newline/CRLF
	data := strings.TrimRight(buf.String(), "\r\n")
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:]), nil
}
