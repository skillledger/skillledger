package ecosystem

import (
	"path/filepath"

	"github.com/spf13/afero"
)

// OpenAIAdapter discovers OpenAI tool definitions.
type OpenAIAdapter struct{}

// Kind returns the ecosystem kind identifier.
func (a *OpenAIAdapter) Kind() string {
	return "openai-tool"
}

// Discover scans OpenAI tool directories.
// Global: ~/.codex/ (shared namespace with Codex)
func (a *OpenAIAdapter) Discover(fs afero.Fs) ([]DiscoveredSkill, error) {
	configFiles := []string{"package.json", "plugin.json"}

	home := homeDir()
	if home == "" {
		return nil, nil
	}

	globalDir := filepath.Clean(filepath.Join(home, ".openai", "tools"))
	return discoverSkillsInDir(fs, globalDir, a.Kind(), configFiles)
}
