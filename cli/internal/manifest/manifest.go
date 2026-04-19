package manifest

// Manifest represents a SkillLedger artifact manifest.
type Manifest struct {
	SkillLedger  int            `yaml:"skillledger" json:"skillledger"`
	ID           string         `yaml:"id" json:"id"`
	Version      string         `yaml:"version" json:"version"`
	Kind         string         `yaml:"kind" json:"kind"`
	Source       Source         `yaml:"source" json:"source"`
	Build        *Build         `yaml:"build,omitempty" json:"build,omitempty"`
	Capabilities Capabilities   `yaml:"capabilities" json:"capabilities"`
	Attestation  *Attestation   `yaml:"attestation,omitempty" json:"attestation,omitempty"`
	Profile      map[string]any `yaml:"profile,omitempty" json:"profile,omitempty"`
}

// Source identifies the git repository containing the skill source code.
type Source struct {
	Repository string `yaml:"repository" json:"repository"`
	Ref        string `yaml:"ref,omitempty" json:"ref,omitempty"`
	Directory  string `yaml:"directory,omitempty" json:"directory,omitempty"`
}

// Build defines the build configuration for deterministic artifact creation.
type Build struct {
	Command      string            `yaml:"command,omitempty" json:"command,omitempty"`
	Env          map[string]string `yaml:"env,omitempty" json:"env,omitempty"`
	Reproducible *bool             `yaml:"reproducible,omitempty" json:"reproducible,omitempty"`
}

// Capabilities declares the permissions the skill requires.
type Capabilities struct {
	Filesystem []string `yaml:"filesystem,omitempty" json:"filesystem,omitempty"`
	Network    []string `yaml:"network,omitempty" json:"network,omitempty"`
	Secrets    []string `yaml:"secrets,omitempty" json:"secrets,omitempty"`
	Tools      []string `yaml:"tools,omitempty" json:"tools,omitempty"`
}

// Attestation contains signing and provenance metadata.
type Attestation struct {
	SignedBy        string `yaml:"signed_by,omitempty" json:"signed_by,omitempty"`
	TransparencyLog string `yaml:"transparency_log,omitempty" json:"transparency_log,omitempty"`
	Provenance      string `yaml:"provenance,omitempty" json:"provenance,omitempty"`
}
