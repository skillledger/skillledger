package ecosystem

import (
	"path/filepath"

	"github.com/spf13/afero"
)

// OpenClawAdapter discovers OpenClaw plugins.
type OpenClawAdapter struct{}

// Kind returns the ecosystem kind identifier.
func (a *OpenClawAdapter) Kind() string {
	return "openclaw-plugin"
}

// Discover scans OpenClaw extension directories.
// Global: ~/.openclaw/extensions/
// Project-local: ./.openclaw/extensions/
func (a *OpenClawAdapter) Discover(fs afero.Fs) ([]DiscoveredSkill, error) {
	var all []DiscoveredSkill
	configFiles := []string{"openclaw.plugin.json", "plugin.json", "package.json"}

	// Global extensions
	home := homeDir()
	if home != "" {
		globalDir := filepath.Clean(filepath.Join(home, ".openclaw", "extensions"))
		found, err := discoverSkillsInDir(fs, globalDir, a.Kind(), configFiles)
		if err != nil {
			return nil, err
		}
		all = append(all, found...)
	}

	// Project-local extensions
	localDir := filepath.Clean(filepath.Join(".", ".openclaw", "extensions"))
	found, err := discoverSkillsInDir(fs, localDir, a.Kind(), configFiles)
	if err != nil {
		return nil, err
	}
	all = append(all, found...)

	return all, nil
}
