package ecosystem

import (
	"path/filepath"

	"github.com/spf13/afero"
)

// OpenCodeAdapter discovers OpenCode tools.
type OpenCodeAdapter struct{}

// Kind returns the ecosystem kind identifier.
func (a *OpenCodeAdapter) Kind() string {
	return "opencode"
}

// Discover scans OpenCode tool directories.
// Global: ~/.config/opencode/tools/
// Project-local: ./.opencode/tools/
func (a *OpenCodeAdapter) Discover(fs afero.Fs) ([]DiscoveredSkill, error) {
	var all []DiscoveredSkill
	configFiles := []string{"package.json", "plugin.json"}

	// Global tools
	home := homeDir()
	if home != "" {
		globalDir := filepath.Clean(filepath.Join(home, ".config", "opencode", "tools"))
		found, err := discoverSkillsInDir(fs, globalDir, a.Kind(), configFiles)
		if err != nil {
			return nil, err
		}
		all = append(all, found...)
	}

	// Project-local tools
	localDir := filepath.Clean(filepath.Join(".", ".opencode", "tools"))
	found, err := discoverSkillsInDir(fs, localDir, a.Kind(), configFiles)
	if err != nil {
		return nil, err
	}
	all = append(all, found...)

	return all, nil
}
