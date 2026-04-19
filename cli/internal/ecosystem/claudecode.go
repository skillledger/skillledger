package ecosystem

import (
	"path/filepath"

	"github.com/spf13/afero"
)

// ClaudeCodeAdapter discovers Claude Code skills.
type ClaudeCodeAdapter struct{}

// Kind returns the ecosystem kind identifier.
func (a *ClaudeCodeAdapter) Kind() string {
	return "claude-code-skill"
}

// Discover scans Claude Code skill directories.
// Global: ~/.claude/skills/
// Project-local: ./.claude/skills/ (relative to cwd)
func (a *ClaudeCodeAdapter) Discover(fs afero.Fs) ([]DiscoveredSkill, error) {
	var all []DiscoveredSkill
	configFiles := []string{"SKILL.md"}

	// Global skills
	home := homeDir()
	if home != "" {
		globalDir := filepath.Clean(filepath.Join(home, ".claude", "skills"))
		found, err := discoverSkillsInDir(fs, globalDir, a.Kind(), configFiles)
		if err != nil {
			return nil, err
		}
		all = append(all, found...)
	}

	// Project-local skills
	localDir := filepath.Clean(filepath.Join(".", ".claude", "skills"))
	found, err := discoverSkillsInDir(fs, localDir, a.Kind(), configFiles)
	if err != nil {
		return nil, err
	}
	all = append(all, found...)

	return all, nil
}
