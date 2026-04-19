package ecosystem

import (
	"path/filepath"
	"runtime"

	"github.com/spf13/afero"
)

// MCPAdapter discovers MCP (Model Context Protocol) servers from config.
type MCPAdapter struct{}

// Kind returns the ecosystem kind identifier.
func (a *MCPAdapter) Kind() string {
	return "mcp-server"
}

// Discover parses MCP config to find registered servers.
// macOS: ~/Library/Application Support/Claude/claude_desktop_config.json
// Linux: ~/.config/Claude/claude_desktop_config.json
func (a *MCPAdapter) Discover(fs afero.Fs) ([]DiscoveredSkill, error) {
	home := homeDir()
	if home == "" {
		return nil, nil
	}

	var configPath string
	switch runtime.GOOS {
	case "darwin":
		configPath = filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
	default:
		configPath = filepath.Join(home, ".config", "Claude", "claude_desktop_config.json")
	}
	configPath = filepath.Clean(configPath)

	return discoverFromConfig(fs, configPath, a.Kind(), "mcpServers")
}
