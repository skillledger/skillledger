package allowlist

import _ "embed"

//go:embed allowlist.rego
var AllowlistRego string

// Entry defines a trusted publisher identity.
type Entry struct {
	CertIdentity string `json:"cert_identity"`
	Issuer       string `json:"issuer"`
}

// Allowlist holds publisher trust entries.
type Allowlist struct {
	entries []Entry
}

// Load creates an Allowlist from a slice of entries.
func Load(entries []Entry) *Allowlist {
	return nil // stub
}

// IsEmpty returns true if no allowlist entries are configured.
func (a *Allowlist) IsEmpty() bool {
	return false // stub
}

// ToRegoData converts the allowlist to OPA data format.
func (a *Allowlist) ToRegoData() map[string]any {
	return nil // stub
}
