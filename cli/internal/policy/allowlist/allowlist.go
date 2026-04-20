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
	return &Allowlist{entries: entries}
}

// IsEmpty returns true if no allowlist entries are configured.
func (a *Allowlist) IsEmpty() bool {
	return len(a.entries) == 0
}

// ToRegoData converts the allowlist to OPA data format.
// Returns map suitable for rego.Data().
func (a *Allowlist) ToRegoData() map[string]any {
	items := make([]any, len(a.entries))
	for i, e := range a.entries {
		items[i] = map[string]any{
			"cert_identity": e.CertIdentity,
			"issuer":        e.Issuer,
		}
	}
	return map[string]any{
		"publishers": map[string]any{
			"allowlist": items,
		},
	}
}
