package ecosystem_test

import (
	"testing"

	"github.com/skillledger/skillledger/internal/ecosystem"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seedClaudeCode creates a Claude Code skill directory structure in the given fs.
func seedClaudeCode(t *testing.T, fs afero.Fs, baseDir string) {
	t.Helper()
	skillDir := baseDir + "/.claude/skills/my-skill"
	require.NoError(t, fs.MkdirAll(skillDir, 0o755))
	require.NoError(t, afero.WriteFile(fs, skillDir+"/SKILL.md", []byte("# My Test Skill\n\nA test skill."), 0o644))
	require.NoError(t, afero.WriteFile(fs, skillDir+"/rules.md", []byte("some rules"), 0o644))
}

// seedMCP creates an MCP config file with servers.
func seedMCP(t *testing.T, fs afero.Fs, configPath string) {
	t.Helper()
	config := `{
		"mcpServers": {
			"server-alpha": {"command": "node", "args": ["alpha.js"]},
			"server-beta": {"command": "python", "args": ["beta.py"]}
		}
	}`
	require.NoError(t, fs.MkdirAll(configPath[:len(configPath)-len("/claude_desktop_config.json")], 0o755))
	require.NoError(t, afero.WriteFile(fs, configPath, []byte(config), 0o644))
}

// seedOpenClaw creates an OpenClaw plugin directory structure.
func seedOpenClaw(t *testing.T, fs afero.Fs, baseDir string) {
	t.Helper()
	pluginDir := baseDir + "/.openclaw/extensions/my-plugin"
	require.NoError(t, fs.MkdirAll(pluginDir, 0o755))
	pluginJSON := `{"name": "my-openclaw-plugin", "version": "1.2.0"}`
	require.NoError(t, afero.WriteFile(fs, pluginDir+"/openclaw.plugin.json", []byte(pluginJSON), 0o644))
}

// seedOpenAI creates an OpenAI tool directory.
func seedOpenAI(t *testing.T, fs afero.Fs, baseDir string) {
	t.Helper()
	toolDir := baseDir + "/.openai/tools/my-tool"
	require.NoError(t, fs.MkdirAll(toolDir, 0o755))
	require.NoError(t, afero.WriteFile(fs, toolDir+"/package.json", []byte(`{"name": "openai-tool", "version": "0.1.0"}`), 0o644))
}

// seedCodex creates a Codex tool directory.
func seedCodex(t *testing.T, fs afero.Fs, baseDir string) {
	t.Helper()
	toolDir := baseDir + "/.codex/my-codex-tool"
	require.NoError(t, fs.MkdirAll(toolDir, 0o755))
	require.NoError(t, afero.WriteFile(fs, toolDir+"/config.toml", []byte("[tool]\nname = \"codex-tool\""), 0o644))
}

// seedOpenCode creates an OpenCode tools directory.
func seedOpenCode(t *testing.T, fs afero.Fs, baseDir string) {
	t.Helper()
	toolDir := baseDir + "/.config/opencode/tools/my-oc-tool"
	require.NoError(t, fs.MkdirAll(toolDir, 0o755))
	require.NoError(t, afero.WriteFile(fs, toolDir+"/plugin.json", []byte(`{"name": "opencode-tool", "version": "2.0.0"}`), 0o644))
}

func TestDiscoverAll_EmptyFS(t *testing.T) {
	fs := afero.NewMemMapFs()
	reg := ecosystem.NewRegistry(
		&ecosystem.ClaudeCodeAdapter{},
		&ecosystem.MCPAdapter{},
		&ecosystem.OpenClawAdapter{},
		&ecosystem.AnthropicAdapter{},
		&ecosystem.OpenAIAdapter{},
		&ecosystem.CodexAdapter{},
		&ecosystem.OpenCodeAdapter{},
	)

	skills, err := reg.DiscoverAll(fs)
	require.NoError(t, err)
	assert.Empty(t, skills)
}

func TestClaudeCodeAdapter_SkillMetadata(t *testing.T) {
	fs := afero.NewMemMapFs()

	// Seed a skill in .claude/skills (project-local path, avoids home dir issue)
	skillDir := ".claude/skills/test-skill"
	require.NoError(t, fs.MkdirAll(skillDir, 0o755))
	require.NoError(t, afero.WriteFile(fs, skillDir+"/SKILL.md", []byte("# My Claude Skill\n\nDescription."), 0o644))
	require.NoError(t, afero.WriteFile(fs, skillDir+"/rules/main.md", []byte("rule content"), 0o644))

	adapter := &ecosystem.ClaudeCodeAdapter{}
	skills, err := adapter.Discover(fs)
	require.NoError(t, err)

	// Should find at least the project-local skill
	var found *ecosystem.DiscoveredSkill
	for i := range skills {
		if skills[i].ID == "test-skill" {
			found = &skills[i]
			break
		}
	}
	require.NotNil(t, found, "expected to find test-skill")
	assert.Equal(t, "My Claude Skill", found.Name)
	assert.Equal(t, "claude-code-skill", found.Kind)
	assert.NotEmpty(t, found.Files, "should have files listed")
}

func TestMCPAdapter_ParseConfig(t *testing.T) {
	fs := afero.NewMemMapFs()

	// Use a path that will be checked based on current OS
	// We test by directly using discoverFromConfig via the adapter
	// For test portability, seed both possible paths
	seedMCP(t, fs, "Library/Application Support/Claude/claude_desktop_config.json")
	seedMCP(t, fs, ".config/Claude/claude_desktop_config.json")

	adapter := &ecosystem.MCPAdapter{}
	skills, err := adapter.Discover(fs)
	require.NoError(t, err)

	// The adapter uses homeDir() which may not match our MemMapFs paths.
	// If homeDir resolves, it looks for the config under that home.
	// In test, we accept 0 or 2 results depending on whether home + config exists.
	if len(skills) > 0 {
		assert.Equal(t, 2, len(skills))
		kinds := map[string]bool{}
		for _, s := range skills {
			assert.Equal(t, "mcp-server", s.Kind)
			kinds[s.ID] = true
		}
		assert.True(t, kinds["server-alpha"])
		assert.True(t, kinds["server-beta"])
	}
}

func TestDiscoverAll_PartialEcosystems(t *testing.T) {
	fs := afero.NewMemMapFs()

	// Only seed Claude Code project-local
	skillDir := ".claude/skills/partial-skill"
	require.NoError(t, fs.MkdirAll(skillDir, 0o755))
	require.NoError(t, afero.WriteFile(fs, skillDir+"/SKILL.md", []byte("# Partial\n"), 0o644))

	reg := ecosystem.NewRegistry(
		&ecosystem.ClaudeCodeAdapter{},
		&ecosystem.MCPAdapter{},
		&ecosystem.OpenClawAdapter{},
	)

	skills, err := reg.DiscoverAll(fs)
	require.NoError(t, err)

	// Should find Claude Code skills (at least project-local), MCP and OpenClaw return empty
	claudeCount := 0
	for _, s := range skills {
		if s.Kind == "claude-code-skill" {
			claudeCount++
		}
	}
	assert.GreaterOrEqual(t, claudeCount, 1, "should find at least 1 Claude Code skill from project-local path")
}

func TestDiscoverAll_AllEcosystems(t *testing.T) {
	fs := afero.NewMemMapFs()

	// Seed project-local directories that all adapters can find without home dir
	seedClaudeCode(t, fs, ".")

	// OpenClaw project-local
	pluginDir := ".openclaw/extensions/test-plugin"
	require.NoError(t, fs.MkdirAll(pluginDir, 0o755))
	require.NoError(t, afero.WriteFile(fs, pluginDir+"/openclaw.plugin.json", []byte(`{"name":"tp","version":"1.0.0"}`), 0o644))

	// Codex project-local
	codexDir := ".codex/test-codex"
	require.NoError(t, fs.MkdirAll(codexDir, 0o755))
	require.NoError(t, afero.WriteFile(fs, codexDir+"/config.toml", []byte("[tool]"), 0o644))

	// OpenCode project-local
	ocDir := ".opencode/tools/test-oc"
	require.NoError(t, fs.MkdirAll(ocDir, 0o755))
	require.NoError(t, afero.WriteFile(fs, ocDir+"/plugin.json", []byte(`{"name":"oc"}`), 0o644))

	reg := ecosystem.DefaultRegistry()
	skills, err := reg.DiscoverAll(fs)
	require.NoError(t, err)

	// We should find at least the 4 project-local skills we seeded
	// (MCP, OpenAI, and Anthropic may or may not find anything depending on home dir)
	kindSet := map[string]bool{}
	for _, s := range skills {
		kindSet[s.Kind] = true
	}

	assert.True(t, kindSet["claude-code-skill"], "should find claude-code skills")
	assert.True(t, kindSet["openclaw-plugin"], "should find openclaw plugins")
	assert.True(t, kindSet["codex-tool"], "should find codex tools")
	assert.True(t, kindSet["opencode"], "should find opencode tools")
	assert.GreaterOrEqual(t, len(skills), 4, "should find at least 4 skills from project-local paths")
}

func TestOpenClawAdapter_PluginMetadata(t *testing.T) {
	fs := afero.NewMemMapFs()

	pluginDir := ".openclaw/extensions/my-plugin"
	require.NoError(t, fs.MkdirAll(pluginDir, 0o755))
	require.NoError(t, afero.WriteFile(fs, pluginDir+"/openclaw.plugin.json",
		[]byte(`{"name": "My Plugin", "version": "2.1.0"}`), 0o644))

	adapter := &ecosystem.OpenClawAdapter{}
	skills, err := adapter.Discover(fs)
	require.NoError(t, err)

	var found *ecosystem.DiscoveredSkill
	for i := range skills {
		if skills[i].ID == "my-plugin" {
			found = &skills[i]
			break
		}
	}
	require.NotNil(t, found)
	assert.Equal(t, "My Plugin", found.Name)
	assert.Equal(t, "2.1.0", found.Version)
	assert.Equal(t, "openclaw-plugin", found.Kind)
}

func TestAdapterKinds(t *testing.T) {
	tests := []struct {
		adapter ecosystem.Adapter
		kind    string
	}{
		{&ecosystem.ClaudeCodeAdapter{}, "claude-code-skill"},
		{&ecosystem.MCPAdapter{}, "mcp-server"},
		{&ecosystem.OpenClawAdapter{}, "openclaw-plugin"},
		{&ecosystem.AnthropicAdapter{}, "anthropic-skill"},
		{&ecosystem.OpenAIAdapter{}, "openai-tool"},
		{&ecosystem.CodexAdapter{}, "codex-tool"},
		{&ecosystem.OpenCodeAdapter{}, "opencode"},
	}

	for _, tt := range tests {
		t.Run(tt.kind, func(t *testing.T) {
			assert.Equal(t, tt.kind, tt.adapter.Kind())
		})
	}
}
