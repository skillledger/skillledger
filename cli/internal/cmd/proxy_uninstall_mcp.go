package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var proxyUninstallMCPCmd = &cobra.Command{
	Use:   "uninstall-mcp",
	Short: "Restore original MCP client configuration",
	Long: `Restores the Claude Desktop MCP configuration from the backup created by
'skillledger proxy install-mcp'. The original server commands and arguments
are restored, and the backup file is removed.`,
	RunE: runProxyUninstallMCP,
}

func runProxyUninstallMCP(cmd *cobra.Command, args []string) error {
	configPath, _ := cmd.Flags().GetString("config")
	if configPath == "" {
		configPath = defaultMCPConfigPath()
	}

	backupPath := filepath.Join(filepath.Dir(configPath), ".skillledger-mcp-backup.json")

	// Read backup.
	backupData, err := os.ReadFile(backupPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("no MCP proxy backup found -- was `proxy install-mcp` run?")
		}
		return fmt.Errorf("reading backup: %w", err)
	}

	var backup map[string]mcpBackupEntry
	if err := json.Unmarshal(backupData, &backup); err != nil {
		return fmt.Errorf("parsing backup: %w", err)
	}

	// Read current config.
	configData, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("reading MCP config: %w", err)
	}

	var config map[string]json.RawMessage
	if err := json.Unmarshal(configData, &config); err != nil {
		return fmt.Errorf("parsing MCP config: %w", err)
	}

	serversRaw, ok := config["mcpServers"]
	if !ok {
		return fmt.Errorf("no mcpServers key found in MCP config")
	}

	var servers map[string]json.RawMessage
	if err := json.Unmarshal(serversRaw, &servers); err != nil {
		return fmt.Errorf("parsing mcpServers: %w", err)
	}

	restored := 0
	for name, original := range backup {
		serverRaw, exists := servers[name]
		if !exists {
			log.Warn().Str("server", name).Msg("server not found in current config, skipping restore")
			continue
		}

		// Parse current entry to preserve extra fields.
		var fullEntry map[string]json.RawMessage
		if err := json.Unmarshal(serverRaw, &fullEntry); err != nil {
			fullEntry = make(map[string]json.RawMessage)
		}

		// Restore original command and args.
		cmdJSON, _ := json.Marshal(original.Command)
		argsJSON, _ := json.Marshal(original.Args)
		fullEntry["command"] = json.RawMessage(cmdJSON)
		fullEntry["args"] = json.RawMessage(argsJSON)

		merged, err := json.Marshal(fullEntry)
		if err != nil {
			return fmt.Errorf("marshaling restored entry for %s: %w", name, err)
		}
		servers[name] = json.RawMessage(merged)
		restored++
	}

	// Write restored config.
	updatedServers, err := json.Marshal(servers)
	if err != nil {
		return fmt.Errorf("marshaling restored servers: %w", err)
	}
	config["mcpServers"] = json.RawMessage(updatedServers)

	updatedConfig, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling restored config: %w", err)
	}

	if err := os.WriteFile(configPath, updatedConfig, 0644); err != nil {
		return fmt.Errorf("writing restored config: %w", err)
	}

	// Remove backup file.
	if err := os.Remove(backupPath); err != nil {
		log.Warn().Err(err).Msg("failed to remove backup file")
	}

	log.Info().Int("count", restored).Msg("Restored MCP server entries to original configuration")
	return nil
}

func init() {
	proxyUninstallMCPCmd.Flags().String("config", "", "path to MCP config file (overrides OS default)")
}
