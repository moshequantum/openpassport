package passport

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path"
	"strings"
)

const DefaultPlaceholder = "0000000000000000000000000000000000000000000000000000000000000000"

func Sha256Bytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ToLF converts CRLF and lone CR line endings to LF without trimming leading/trailing whitespace.
func ToLF(data []byte) []byte {
	str := string(data)
	str = strings.ReplaceAll(str, "\r\n", "\n")
	str = strings.ReplaceAll(str, "\r", "\n")
	return []byte(str)
}

func HasCRLF(data []byte) bool {
	return bytes.Contains(data, []byte{0x0d})
}

// IsValidHex64 reports whether s is exactly 64 lowercase hexadecimal characters [0-9a-f].
func IsValidHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// IsTextFile reports whether relPath should obey the strict LF text line-ending contract.
func IsTextFile(relPath string) bool {
	slash := strings.ReplaceAll(relPath, "\\", "/")
	base := path.Base(slash)
	if base == ".gitattributes" || base == "LICENSE" {
		return true
	}
	ext := strings.ToLower(path.Ext(base))
	return ext == ".md" || ext == ".json" || ext == ".txt" || ext == ".html"
}

// ComputeManifestSelfHashFromBytes implements the canonical OpenPassport v1.0 self-hash contract:
// It locates the single "manifest.json" entry inside the top-level "files" JSON array,
// replaces only that entry's "sha256" string value matching currentHash (case-insensitive)
// with placeholder while preserving surrounding bytes, ensures LF line endings, and computes SHA-256.
// Fails closed by returning "" if currentHash is not valid hex64 or the manifest entry is missing/ambiguous.
func ComputeManifestSelfHashFromBytes(rawContent []byte, currentHash, placeholder string) string {
	if !IsValidHex64(strings.ToLower(currentHash)) {
		return ""
	}
	if placeholder == "" {
		placeholder = DefaultPlaceholder
	}
	encodedPlaceholder, err := json.Marshal(placeholder)
	if err != nil || len(encodedPlaceholder) < 2 {
		return ""
	}
	placeholderInner := encodedPlaceholder[1 : len(encodedPlaceholder)-1]

	start, end, foundHash, ok := findManifestSha256Span(rawContent)
	if !ok {
		return ""
	}
	if !strings.EqualFold(foundHash, currentHash) {
		return ""
	}

	replaced := make([]byte, 0, len(rawContent)-(end-start)+len(placeholderInner))
	replaced = append(replaced, rawContent[:start]...)
	replaced = append(replaced, placeholderInner...)
	replaced = append(replaced, rawContent[end:]...)

	norm := ToLF(replaced)
	return Sha256Bytes(norm)
}

func skipJSONWhitespace(raw []byte, pos int) int {
	for pos < len(raw) {
		switch raw[pos] {
		case ' ', '\t', '\n', '\r':
			pos++
		default:
			return pos
		}
	}
	return pos
}

func scanJSONString(raw []byte, pos int) (start, end int, val string, ok bool) {
	if pos >= len(raw) || raw[pos] != '"' {
		return 0, 0, "", false
	}
	start = pos
	i := pos + 1
	for i < len(raw) {
		if raw[i] == '\\' {
			i += 2
			continue
		}
		if raw[i] == '"' {
			end = i + 1
			if err := json.Unmarshal(raw[start:end], &val); err != nil {
				return 0, 0, "", false
			}
			return start, end, val, true
		}
		i++
	}
	return 0, 0, "", false
}

func skipJSONValue(raw []byte, pos int) (int, bool) {
	pos = skipJSONWhitespace(raw, pos)
	if pos >= len(raw) {
		return 0, false
	}
	switch raw[pos] {
	case '"':
		_, end, _, ok := scanJSONString(raw, pos)
		return end, ok
	case '{', '[':
		depth := 0
		for pos < len(raw) {
			switch raw[pos] {
			case '"':
				_, end, _, ok := scanJSONString(raw, pos)
				if !ok {
					return 0, false
				}
				pos = end
				continue
			case '{', '[':
				depth++
			case '}', ']':
				depth--
				if depth == 0 {
					return pos + 1, true
				}
			}
			pos++
		}
		return 0, false
	default:
		for pos < len(raw) {
			switch raw[pos] {
			case ' ', '\t', '\n', '\r', ',', '}', ']':
				return pos, true
			}
			pos++
		}
		return pos, true
	}
}

func findManifestSha256Span(raw []byte) (start, end int, shaVal string, ok bool) {
	if !json.Valid(raw) {
		return 0, 0, "", false
	}
	pos := skipJSONWhitespace(raw, 0)
	if pos >= len(raw) || raw[pos] != '{' {
		return 0, 0, "", false
	}
	pos++

	var (
		foundFiles bool
		matchCount int
		matchStart int
		matchEnd   int
		matchSha   string
	)

	for {
		pos = skipJSONWhitespace(raw, pos)
		if pos >= len(raw) {
			return 0, 0, "", false
		}
		if raw[pos] == '}' {
			pos++
			break
		}

		_, keyEnd, key, ok := scanJSONString(raw, pos)
		if !ok {
			return 0, 0, "", false
		}
		pos = skipJSONWhitespace(raw, keyEnd)
		if pos >= len(raw) || raw[pos] != ':' {
			return 0, 0, "", false
		}
		pos = skipJSONWhitespace(raw, pos+1)

		if key == "files" {
			if foundFiles {
				return 0, 0, "", false
			}
			foundFiles = true
			if pos >= len(raw) || raw[pos] != '[' {
				return 0, 0, "", false
			}
			pos++

			for {
				pos = skipJSONWhitespace(raw, pos)
				if pos >= len(raw) {
					return 0, 0, "", false
				}
				if raw[pos] == ']' {
					pos++
					break
				}

				if raw[pos] == '{' {
					pos++
					var (
						pathCount       int
						pathVal         string
						sawManifestPath bool
						shaCount        int
						shaStart        int
						shaEnd          int
						entrySha        string
					)
					for {
						pos = skipJSONWhitespace(raw, pos)
						if pos >= len(raw) {
							return 0, 0, "", false
						}
						if raw[pos] == '}' {
							pos++
							break
						}

						_, fKeyEnd, fKey, ok := scanJSONString(raw, pos)
						if !ok {
							return 0, 0, "", false
						}
						pos = skipJSONWhitespace(raw, fKeyEnd)
						if pos >= len(raw) || raw[pos] != ':' {
							return 0, 0, "", false
						}
						pos = skipJSONWhitespace(raw, pos+1)
						if pos >= len(raw) {
							return 0, 0, "", false
						}

						if fKey == "path" && raw[pos] == '"' {
							_, vEnd, vStr, ok := scanJSONString(raw, pos)
							if !ok {
								return 0, 0, "", false
							}
							pathCount++
							pathVal = vStr
							if vStr == "manifest.json" {
								sawManifestPath = true
							}
							pos = vEnd
						} else if fKey == "sha256" && raw[pos] == '"' {
							vStart, vEnd, vStr, ok := scanJSONString(raw, pos)
							if !ok {
								return 0, 0, "", false
							}
							shaCount++
							shaStart = vStart + 1
							shaEnd = vEnd - 1
							entrySha = vStr
							pos = vEnd
						} else {
							nextPos, ok := skipJSONValue(raw, pos)
							if !ok {
								return 0, 0, "", false
							}
							pos = nextPos
						}

						pos = skipJSONWhitespace(raw, pos)
						if pos < len(raw) && raw[pos] == ',' {
							pos++
						}
					}

					if sawManifestPath {
						if pathCount != 1 || pathVal != "manifest.json" || shaCount != 1 {
							return 0, 0, "", false
						}
						matchCount++
						matchStart = shaStart
						matchEnd = shaEnd
						matchSha = entrySha
					}
				} else {
					nextPos, ok := skipJSONValue(raw, pos)
					if !ok {
						return 0, 0, "", false
					}
					pos = nextPos
				}

				pos = skipJSONWhitespace(raw, pos)
				if pos < len(raw) && raw[pos] == ',' {
					pos++
				}
			}
		} else {
			nextPos, ok := skipJSONValue(raw, pos)
			if !ok {
				return 0, 0, "", false
			}
			pos = nextPos
		}

		pos = skipJSONWhitespace(raw, pos)
		if pos < len(raw) && raw[pos] == ',' {
			pos++
		}
	}

	if !foundFiles || matchCount != 1 {
		return 0, 0, "", false
	}
	return matchStart, matchEnd, matchSha, true
}
