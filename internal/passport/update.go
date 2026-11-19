package passport

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultReleasesAPIURL points to the official OpenPassport GitHub Releases endpoint.
const DefaultReleasesAPIURL = "https://api.github.com/repos/moshequantum/openpassport/releases/latest"

// UpdateReport summarizes the release check and cryptographic SHA256SUMS availability.
type UpdateReport struct {
	CurrentVersion string `json:"currentVersion"`
	LatestVersion  string `json:"latestVersion"`
	UpdateNeeded   bool   `json:"updateNeeded"`
	HasSHA256Sums  bool   `json:"hasSha256Sums"`
	SHA256SumsURL  string `json:"sha256SumsUrl,omitempty"`
	InstallCommand string `json:"installCommand"`
}

type githubReleasePayload struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

// CheckUpdate queries the releases endpoint and verifies whether a newer release with SHA256SUMS is available.
func CheckUpdate(ctx context.Context, currentVersion, releaseAPIURL string) (*UpdateReport, error) {
	if releaseAPIURL == "" {
		releaseAPIURL = DefaultReleasesAPIURL
	}
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, releaseAPIURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating update request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "openpassport-cli")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching latest release: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("releases endpoint returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("reading release payload: %w", err)
	}

	var rel githubReleasePayload
	if err := json.Unmarshal(body, &rel); err != nil {
		return nil, fmt.Errorf("parsing release payload: %w", err)
	}
	if rel.TagName == "" {
		return nil, fmt.Errorf("release payload missing tag_name")
	}

	var sumsURL string
	for _, a := range rel.Assets {
		if a.Name == "SHA256SUMS" {
			sumsURL = a.BrowserDownloadURL
			break
		}
	}

	normCur := strings.TrimPrefix(strings.TrimSpace(currentVersion), "v")
	normLat := strings.TrimPrefix(strings.TrimSpace(rel.TagName), "v")
	updateNeeded := normCur == "" || normCur == "dev" || normCur != normLat

	return &UpdateReport{
		CurrentVersion: currentVersion,
		LatestVersion:  rel.TagName,
		UpdateNeeded:   updateNeeded,
		HasSHA256Sums:  sumsURL != "",
		SHA256SumsURL:  sumsURL,
		InstallCommand: fmt.Sprintf("go install github.com/moshequantum/openpassport/cmd/openpassport@%s", rel.TagName),
	}, nil
}

// VerifyBinaryAgainstSHA256Sums validates binaryBytes against the expected entry for binaryName in a SHA256SUMS manifest.
func VerifyBinaryAgainstSHA256Sums(binaryBytes []byte, binaryName, sha256SumsContent string) (string, error) {
	if binaryName == "" {
		return "", fmt.Errorf("binaryName is required")
	}
	computed := Sha256Bytes(binaryBytes)
	lines := strings.Split(string(ToLF([]byte(sha256SumsContent))), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		hash := strings.ToLower(fields[0])
		name := strings.TrimPrefix(fields[len(fields)-1], "*")
		name = strings.TrimPrefix(name, "dist/")
		if name == binaryName {
			if !IsValidHex64(hash) {
				return "", fmt.Errorf("invalid sha256 entry in SHA256SUMS for %s: %q", binaryName, hash)
			}
			if computed != hash {
				return "", fmt.Errorf("binary sha256 mismatch for %s: expected %s, got %s", binaryName, hash, computed)
			}
			return computed, nil
		}
	}
	return "", fmt.Errorf("entry for %s not found in SHA256SUMS", binaryName)
}
