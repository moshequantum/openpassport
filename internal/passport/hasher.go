package passport

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

const DefaultPlaceholder = "0000000000000000000000000000000000000000000000000000000000000000"

func Sha256Bytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func ToLF(data []byte) []byte {
	str := string(data)
	str = strings.ReplaceAll(str, "\r\n", "\n")
	str = strings.ReplaceAll(str, "\r", "\n")
	str = strings.TrimSpace(str) + "\n"
	return []byte(str)
}

func HasCRLF(data []byte) bool {
	return bytes.Contains(data, []byte{0x0d})
}

// ComputeManifestSelfHashFromBytes implements the canonical OpenPassport v1.0 self-hash contract:
// It takes the raw UTF-8 bytes of manifest.json, replaces the current manifest sha256 with the 64-zeroes placeholder,
// ensures LF, and calculates the SHA-256. This guarantees 100% cross-language determinism.
func ComputeManifestSelfHashFromBytes(rawContent []byte, currentHash, placeholder string) string {
	if placeholder == "" {
		placeholder = DefaultPlaceholder
	}
	text := string(rawContent)
	replaced := strings.Replace(text, currentHash, placeholder, 1)
	norm := ToLF([]byte(replaced))
	return Sha256Bytes(norm)
}
