package ecosystem

import (
	"path/filepath"

	"github.com/spf13/afero"
)

// CodexAdapter discovers Codex tools.
type CodexAdapter struct{}

// Kind returns the ecosystem kind identifier.
func (a *CodexAdapter) Kind() string {
	return "codex-tool"
}

// Discover scans Codex tool directories.
// Global: ~/.codex/
// Project-local: ./.codex/
func (a *CodexAdapter) Discover(fs afero.Fs) ([]DiscoveredSkill, error) {
	var all []DiscoveredSkill
	configFiles := []string{"config.toml", "package.json"}

	// Global tools
	home := homeDir()
	if home != "" {
		globalDir := filepath.Clean(filepath.Join(home, ".codex"))
		found, err := discoverSkillsInDir(fs, globalDir, a.Kind(), configFiles)
		if err != nil {
			return nil, err
		}
		all = append(all, found...)
	}

	// Project-local tools
	localDir := filepath.Clean(filepath.Join(".", ".codex"))
	found, err := discoverSkillsInDir(fs, localDir, a.Kind(), configFiles)
	if err != nil {
		return nil, err
	}
	all = append(all, found...)

	return all, nil
}
