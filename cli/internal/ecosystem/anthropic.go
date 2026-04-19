package ecosystem

import (
	"path/filepath"

	"github.com/spf13/afero"
)

// AnthropicAdapter discovers Anthropic skills.
// Per RESEARCH.md assumption A1, Anthropic skills share paths with Claude Code (~/.claude/skills/).
type AnthropicAdapter struct{}

// Kind returns the ecosystem kind identifier.
func (a *AnthropicAdapter) Kind() string {
	return "anthropic-skill"
}

// Discover scans Anthropic skill directories.
// Global: ~/.claude/skills/ (shared with Claude Code, reported under anthropic-skill kind)
func (a *AnthropicAdapter) Discover(fs afero.Fs) ([]DiscoveredSkill, error) {
	configFiles := []string{"SKILL.md", "package.json"}

	home := homeDir()
	if home == "" {
		return nil, nil
	}

	globalDir := filepath.Clean(filepath.Join(home, ".claude", "skills"))
	return discoverSkillsInDir(fs, globalDir, a.Kind(), configFiles)
}
