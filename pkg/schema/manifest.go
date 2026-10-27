package schema

import "time"

// Layer represents a canonical context layer in OpenPassport.
type Layer struct {
	ID     string `json:"id"`     // e.g., "01"
	Name   string `json:"name"`   // e.g., "IDENTITY"
	Path   string `json:"path"`   // e.g., "01-IDENTITY.md"
	SHA256 string `json:"sha256"` // Hex-encoded SHA-256 hash of the LF-normalized content
}

// ProjectMeta holds basic business identification.
type ProjectMeta struct {
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	Founder     string `json:"founder"`
	Description string `json:"description"`
}

// StackConfig represents the infrastructure choices provisioned by Velo.
type StackConfig struct {
	Frontend string `json:"frontend"` // "astro", "react-vite"
	Runtime  string `json:"runtime"`  // "cloudflare-pages"
	BaaS     string `json:"baas"`     // "insforge"
	Cockpit  string `json:"cockpit"`  // "telegram"
}

// CockpitConfig holds edge gateway specifics.
type CockpitConfig struct {
	TelegramBotHandle string `json:"telegram_bot_handle,omitempty"`
	TelegramOwnerID   string `json:"telegram_owner_id,omitempty"`
}

// Manifest represents the Contract V0 between OpenPassport and Velo.
type Manifest struct {
	Version     string        `json:"version"`      // "1.0.0"
	GeneratedAt time.Time     `json:"generated_at"` // RFC3339
	Project     ProjectMeta   `json:"project"`
	Stack       StackConfig   `json:"stack"`
	Cockpit     CockpitConfig `json:"cockpit,omitempty"`
	Layers      []Layer       `json:"layers"`
	SHA256      string        `json:"sha256"` // Cryptographic seal of the manifest itself
}
