package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var proxyInstallMCPCmd = &cobra.Command{
	Use:   "install-mcp",
	Short: "Configure MCP clients to use the proxy",
	Long: `Rewrites the Claude Desktop MCP configuration so that each MCP server
is launched through the SkillLedger proxy wrapper. The original server
commands and arguments are preserved in a backup file for later restoration
via 'skillledger proxy uninstall-mcp'.

The default config path is OS-dependent:
  macOS:  ~/Library/Application Support/Claude/claude_desktop_config.json
  Linux:  ~/.config/Claude/claude_desktop_config.json

Use --config to override.`,
	RunE: runProxyInstallMCP,
}

// mcpServerEntry represents one MCP server config entry.
type mcpServerEntry struct {
	Command string   `json:"command"`
	Args    []string `json:"args,omitempty"`
}

// mcpBackupEntry stores the original command+args for one server.
type mcpBackupEntry struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
}

func runProxyInstallMCP(cmd *cobra.Command, args []string) error {
	configPath, _ := cmd.Flags().GetString("config")
	if configPath == "" {
		configPath = defaultMCPConfigPath()
	}

	// Read existing config (T-09-10: validate JSON before rewriting).
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("MCP config not found at %s\nSpecify --config or ensure Claude Desktop is installed", configPath)
		}
		return fmt.Errorf("reading MCP config: %w", err)
	}

	var config map[string]json.RawMessage
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("parsing MCP config: %w (file may be corrupted)", err)
	}

	serversRaw, ok := config["mcpServers"]
	if !ok {
		return fmt.Errorf("no mcpServers key found in MCP config")
	}

	var servers map[string]json.RawMessage
	if err := json.Unmarshal(serversRaw, &servers); err != nil {
		return fmt.Errorf("parsing mcpServers: %w", err)
	}

	if len(servers) == 0 {
		log.Info().Msg("No MCP servers found in config -- nothing to do")
		return nil
	}

	// Get the skillledger binary path for wrapper.
	selfPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolving skillledger binary path: %w", err)
	}

	backup := make(map[string]mcpBackupEntry)
	rewritten := 0

	for name, raw := range servers {
		var entry mcpServerEntry
		if err := json.Unmarshal(raw, &entry); err != nil {
			log.Warn().Str("server", name).Err(err).Msg("skipping malformed server entry")
			continue
		}

		if entry.Command == "" {
			log.Warn().Str("server", name).Msg("skipping server with no command")
			continue
		}

		// Skip if already wrapped (idempotent).
		if entry.Command == selfPath {
			log.Debug().Str("server", name).Msg("already wrapped, skipping")
			continue
		}

		// Save original for backup.
		backup[name] = mcpBackupEntry{
			Command: entry.Command,
			Args:    entry.Args,
		}

		// Rewrite to use proxy wrapper.
		newArgs := []string{"proxy", "wrap-mcp", "--skill-id", name, "--"}
		newArgs = append(newArgs, entry.Command)
		newArgs = append(newArgs, entry.Args...)

		entry.Command = selfPath
		entry.Args = newArgs

		rewrittenRaw, err := json.Marshal(entry)
		if err != nil {
			return fmt.Errorf("marshaling rewritten entry for %s: %w", name, err)
		}

		// Merge back: preserve any extra fields in the original server entry.
		var fullEntry map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fullEntry); err != nil {
			fullEntry = make(map[string]json.RawMessage)
		}
		var rewrittenEntry map[string]json.RawMessage
		if err := json.Unmarshal(rewrittenRaw, &rewrittenEntry); err != nil {
			return fmt.Errorf("re-parsing rewritten entry: %w", err)
		}
		for k, v := range rewrittenEntry {
			fullEntry[k] = v
		}

		merged, err := json.Marshal(fullEntry)
		if err != nil {
			return fmt.Errorf("marshaling merged entry for %s: %w", name, err)
		}
		servers[name] = json.RawMessage(merged)
		rewritten++
	}

	if rewritten == 0 {
		log.Info().Msg("All MCP servers already wrapped -- nothing to do")
		return nil
	}

	// Write backup file alongside config (Pitfall 5: store original entries).
	backupPath := filepath.Join(filepath.Dir(configPath), ".skillledger-mcp-backup.json")
	backupData, err := json.MarshalIndent(backup, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling backup: %w", err)
	}
	if err := os.WriteFile(backupPath, backupData, 0644); err != nil {
		return fmt.Errorf("writing backup file: %w", err)
	}

	// Write updated servers back to config.
	updatedServers, err := json.Marshal(servers)
	if err != nil {
		return fmt.Errorf("marshaling updated servers: %w", err)
	}
	config["mcpServers"] = json.RawMessage(updatedServers)

	updatedConfig, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling updated config: %w", err)
	}

	// T-09-10: validate JSON is well-formed before writing.
	var validate json.RawMessage
	if err := json.Unmarshal(updatedConfig, &validate); err != nil {
		return fmt.Errorf("BUG: generated invalid JSON config: %w", err)
	}

	if err := os.WriteFile(configPath, updatedConfig, 0644); err != nil {
		return fmt.Errorf("writing MCP config: %w", err)
	}

	log.Info().Int("count", rewritten).Msg("Rewrote MCP server entries to use proxy wrapper")
	log.Info().Str("backup", backupPath).Msg("Backup saved")

	return nil
}

// defaultMCPConfigPath returns the OS-dependent Claude Desktop config path.
func defaultMCPConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
	default:
		return filepath.Join(home, ".config", "Claude", "claude_desktop_config.json")
	}
}

func init() {
	proxyInstallMCPCmd.Flags().String("config", "", "path to MCP config file (overrides OS default)")
}
