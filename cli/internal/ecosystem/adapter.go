// Package ecosystem provides adapters for discovering installed AI agent skills
// across multiple ecosystems (Claude Code, MCP, OpenClaw, Anthropic, OpenAI, Codex, OpenCode).
package ecosystem

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/afero"
)

// DiscoveredSkill represents a skill found by an ecosystem adapter.
type DiscoveredSkill struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Version  string            `json:"version"`
	Kind     string            `json:"kind"`
	Path     string            `json:"path"`
	Files    []string          `json:"files"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// Adapter discovers installed skills for a specific ecosystem.
type Adapter interface {
	Kind() string
	Discover(fs afero.Fs) ([]DiscoveredSkill, error)
}

// Registry holds all registered ecosystem adapters.
type Registry struct {
	adapters []Adapter
}

// NewRegistry creates a Registry with the given adapters.
func NewRegistry(adapters ...Adapter) *Registry {
	return &Registry{adapters: adapters}
}

// DefaultRegistry returns a registry with all 7 ecosystem adapters.
func DefaultRegistry() *Registry {
	return NewRegistry(
		&ClaudeCodeAdapter{},
		&MCPAdapter{},
		&OpenClawAdapter{},
		&AnthropicAdapter{},
		&OpenAIAdapter{},
		&CodexAdapter{},
		&OpenCodeAdapter{},
	)
}

// DiscoverAll runs all adapters and merges results. Skips adapters whose
// ecosystem directory does not exist (empty result, not error).
// Deduplicates skills by path+files to avoid double-reporting when multiple
// adapters scan overlapping directories (WR-05).
func (r *Registry) DiscoverAll(fs afero.Fs) ([]DiscoveredSkill, error) {
	var all []DiscoveredSkill
	seen := make(map[string]bool)
	for _, a := range r.adapters {
		found, err := a.Discover(fs)
		if err != nil {
			return nil, fmt.Errorf("adapter %s: %w", a.Kind(), err)
		}
		for _, s := range found {
			key := s.Path + "|" + strings.Join(s.Files, ",")
			if !seen[key] {
				seen[key] = true
				all = append(all, s)
			}
		}
	}
	return all, nil
}

// discoverSkillsInDir scans a directory for skill subdirectories.
// Returns nil, nil if the directory does not exist.
func discoverSkillsInDir(fs afero.Fs, dir string, kind string, configFiles []string) ([]DiscoveredSkill, error) {
	dir = filepath.Clean(dir)

	info, err := fs.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("stat %s: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, nil
	}

	entries, err := afero.ReadDir(fs, dir)
	if err != nil {
		return nil, fmt.Errorf("readdir %s: %w", dir, err)
	}

	var skills []DiscoveredSkill
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		skillPath := filepath.Join(dir, entry.Name())
		skill := DiscoveredSkill{
			ID:       entry.Name(),
			Name:     entry.Name(),
			Kind:     kind,
			Path:     skillPath,
			Metadata: make(map[string]string),
		}

		// Collect files
		files, err := collectFiles(fs, skillPath, skillPath)
		if err != nil {
			return nil, fmt.Errorf("walk %s: %w", skillPath, err)
		}
		skill.Files = files

		// Try to extract metadata from config files
		for _, cf := range configFiles {
			cfPath := filepath.Join(skillPath, cf)
			if data, err := afero.ReadFile(fs, cfPath); err == nil {
				extractMetadata(&skill, cf, data)
				break
			}
		}

		skills = append(skills, skill)
	}

	return skills, nil
}

// collectFiles walks a directory and returns relative file paths.
func collectFiles(fs afero.Fs, root, dir string) ([]string, error) {
	entries, err := afero.ReadDir(fs, dir)
	if err != nil {
		return nil, err
	}

	var files []string
	for _, entry := range entries {
		fullPath := filepath.Join(dir, entry.Name())
		if entry.IsDir() {
			sub, err := collectFiles(fs, root, fullPath)
			if err != nil {
				return nil, err
			}
			files = append(files, sub...)
		} else {
			rel, err := filepath.Rel(root, fullPath)
			if err != nil {
				rel = fullPath
			}
			files = append(files, rel)
		}
	}
	return files, nil
}

// extractMetadata parses known config file formats to populate skill metadata.
func extractMetadata(skill *DiscoveredSkill, filename string, data []byte) {
	switch {
	case filename == "SKILL.md":
		// Extract name from first heading
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "# ") {
				skill.Name = strings.TrimPrefix(trimmed, "# ")
				break
			}
		}

	case filename == "package.json" || filename == "plugin.json" || filename == "openclaw.plugin.json":
		var parsed map[string]any
		if err := json.Unmarshal(data, &parsed); err == nil {
			if name, ok := parsed["name"].(string); ok {
				skill.Name = name
			}
			if version, ok := parsed["version"].(string); ok {
				skill.Version = version
			}
		}
	}
}

// discoverFromConfig parses a JSON config file to discover skills.
// Returns nil, nil if the config file does not exist.
func discoverFromConfig(fs afero.Fs, configPath string, kind string, serverKey string) ([]DiscoveredSkill, error) {
	configPath = filepath.Clean(configPath)

	data, err := afero.ReadFile(fs, configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read config %s: %w", configPath, err)
	}

	var config map[string]json.RawMessage
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", configPath, err)
	}

	serversRaw, ok := config[serverKey]
	if !ok {
		return nil, nil
	}

	var servers map[string]json.RawMessage
	if err := json.Unmarshal(serversRaw, &servers); err != nil {
		return nil, nil
	}

	var skills []DiscoveredSkill
	for name := range servers {
		skill := DiscoveredSkill{
			ID:       name,
			Name:     name,
			Kind:     kind,
			Path:     configPath,
			Metadata: map[string]string{"source": "config"},
		}
		skills = append(skills, skill)
	}

	return skills, nil
}

// homeDir returns the user's home directory. This is resolved at call time,
// not at struct construction, per security guidelines.
func homeDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home
}
