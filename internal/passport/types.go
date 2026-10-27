package passport

type PassportFileEntry struct {
	Path       string `json:"path"`
	Layer      string `json:"layer"`
	MediaType  string `json:"mediaType"`
	Sha256     string `json:"sha256"`
	Visibility string `json:"visibility"`
}

type PassportProfile struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	Files       []string `json:"files"`
}

type ManifestSelfHashConfig struct {
	HashMode    string `json:"hashMode"`
	Path        string `json:"path"`
	Placeholder string `json:"placeholder"`
}

type LoadContract struct {
	Bootstrap         []string `json:"bootstrap"`
	FirstContext      string   `json:"firstContext"`
	Then              string   `json:"then"`
	DuplicatesAllowed bool     `json:"duplicatesAllowed"`
}

type TemporalInvariant struct {
	AsOf string `json:"asOf"`
}

type PassportManifest struct {
	SchemaVersion             int                    `json:"schemaVersion"`
	Kind                      string                 `json:"kind"`
	Name                      string                 `json:"name"`
	PackageVersion            string                 `json:"packageVersion"`
	Originator                string                 `json:"originator"`
	TechnicalAuthority        string                 `json:"technicalAuthority,omitempty"`
	Language                  string                 `json:"language"`
	AsOf                      string                 `json:"asOf"`
	UpdatedAt                 string                 `json:"updatedAt"`
	Supersedes                string                 `json:"supersedes,omitempty"`
	RuntimeVerifiedAt         *string                `json:"runtimeVerifiedAt"`
	Ownership                 string                 `json:"ownership"`
	ImplicitMemory            bool                   `json:"implicitMemory"`
	AuthorityGrantedByPackage bool                   `json:"authorityGrantedByPackage"`
	HashAlgorithm             string                 `json:"hashAlgorithm"`
	HashEncoding              string                 `json:"hashEncoding"`
	HashByteContract          string                 `json:"hashByteContract"`
	ManifestSelfHash          ManifestSelfHashConfig `json:"manifestSelfHash"`
	LoadContract              LoadContract           `json:"loadContract"`
	TemporalInvariant         *TemporalInvariant     `json:"temporalInvariant,omitempty"`
	Files                     []PassportFileEntry    `json:"files"`
	Profiles                  []PassportProfile      `json:"profiles"`
}

type ReceiptFileEntry struct {
	Path   string `json:"path"`
	Layer  string `json:"layer"`
	Sha256 string `json:"sha256"`
}

type PassportReceiptInfo struct {
	Name               string             `json:"name"`
	PackageVersion     string             `json:"packageVersion"`
	Originator         string             `json:"originator"`
	TechnicalAuthority string             `json:"technicalAuthority"`
	ManifestSha256     string             `json:"manifestSha256"`
	FileCount          int                `json:"fileCount"`
	Files              []ReceiptFileEntry `json:"files"`
}

type PassportReceipt struct {
	SchemaVersion int                 `json:"schemaVersion"`
	Kind          string              `json:"kind"`
	Status        string              `json:"status"`
	GeneratedAt   string              `json:"generatedAt"`
	AsOf          string              `json:"asOf"`
	Passport      PassportReceiptInfo `json:"passport"`
}
