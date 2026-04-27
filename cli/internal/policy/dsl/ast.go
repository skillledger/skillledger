package dsl

// Policy represents a parsed DSL policy file.
type Policy struct {
	Version      int               `yaml:"version" json:"version"`
	Rules        map[string][]Rule `yaml:"rules" json:"rules"`
	Publishers   PublisherConfig   `yaml:"publishers,omitempty" json:"publishers,omitempty"`
	RuntimeRules *RuntimeRuleSet   `yaml:"runtime-rules,omitempty" json:"runtime-rules,omitempty"`
}

// RuntimeRuleSet holds runtime action enforcement rules compiled to Rego.
// Block rules generate deny decisions, Warn rules generate warnings,
// and Log rules generate log entries for observability.
type RuntimeRuleSet struct {
	Block []string `yaml:"block,omitempty" json:"block,omitempty"`
	Warn  []string `yaml:"warn,omitempty" json:"warn,omitempty"`
	Log   []string `yaml:"log,omitempty" json:"log,omitempty"`
}

// Rule represents a single policy rule in the DSL.
type Rule struct {
	Deny    string   `yaml:"deny,omitempty" json:"deny,omitempty"`
	Warn    string   `yaml:"warn,omitempty" json:"warn,omitempty"`
	Except  []string `yaml:"except,omitempty" json:"except,omitempty"`
	Message string   `yaml:"message" json:"message"`
}

// PublisherConfig holds publisher trust configuration.
type PublisherConfig struct {
	Allowlist []AllowlistEntry `yaml:"allowlist,omitempty" json:"allowlist,omitempty"`
}

// AllowlistEntry defines a trusted publisher identity.
type AllowlistEntry struct {
	CertIdentity string `yaml:"cert-identity" json:"cert_identity"`
	Issuer       string `yaml:"issuer" json:"issuer"`
}
