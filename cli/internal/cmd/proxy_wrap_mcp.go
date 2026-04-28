package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/skillledger/skillledger/internal/proxy"
)

// proxyWrapMCPCmd is a hidden internal command used as the fork-exec entry point
// for MCP server wrapping. The install-mcp command rewrites MCP config entries
// to invoke: skillledger proxy wrap-mcp --skill-id <name> -- <original-command> <args...>
var proxyWrapMCPCmd = &cobra.Command{
	Use:    "wrap-mcp -- <command> [args...]",
	Short:  "Internal: wrap an MCP server through the proxy",
	Hidden: true,
	// ArbitraryArgs because everything after "--" is the real server command.
	Args:                  cobra.ArbitraryArgs,
	DisableFlagParsing:    false,
	TraverseChildren:      true,
	RunE:                  runProxyWrapMCP,
}

func runProxyWrapMCP(cmd *cobra.Command, args []string) error {
	skillID, _ := cmd.Flags().GetString("skill-id")

	if len(args) == 0 {
		return fmt.Errorf("no command specified -- usage: wrap-mcp --skill-id <id> -- <command> [args...]")
	}

	command := args[0]
	var cmdArgs []string
	if len(args) > 1 {
		cmdArgs = args[1:]
	}

	// Create a file-backed decision log for cross-process access.
	dl := proxy.NewDecisionLog(1000)

	// Persist decisions to disk so proxy logs can read MCP stdio events after process exit.
	baseDir := proxyBaseDir()
	decLogPath := filepath.Join(baseDir, "proxy", "decisions.jsonl")
	if err := os.MkdirAll(filepath.Dir(decLogPath), 0o755); err != nil {
		log.Warn().Err(err).Msg("failed to create proxy directory for decisions log")
	}
	if f, err := os.OpenFile(decLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err != nil {
		log.Warn().Err(err).Msg("failed to open decisions.jsonl for writing -- decisions will be memory-only")
	} else {
		dl.SetFileWriter(f)
		defer f.Close()
	}

	// Construct ToolPinStore for rug-pull detection.
	pinStorePath := filepath.Join(baseDir, "proxy", "pin-store.json")
	pinStore := proxy.NewToolPinStore(pinStorePath)

	// Construct InjectionScanner for prompt injection detection.
	injScanner := proxy.NewInjectionScanner(nil)

	// Load layered PolicyConfig (same approach as proxy start).
	config := proxy.DefaultPolicyConfig()
	for _, path := range []string{
		filepath.Join(baseDir, "proxy", "policy.yaml"),
		filepath.Join(".", ".skillledger", "policy.yaml"),
	} {
		if data, readErr := os.ReadFile(path); readErr == nil {
			if fc, parseErr := proxy.LoadPolicyConfig(data); parseErr == nil {
				config = proxy.MergePolicyConfigs(config, fc)
			}
		}
	}

	wrapper, err := proxy.NewMCPWrapper(command, cmdArgs, skillID, dl, log.Logger, pinStore, injScanner, config)
	if err != nil {
		return fmt.Errorf("creating MCP wrapper: %w", err)
	}

	log.Debug().
		Str("command", command).
		Str("skill_id", skillID).
		Msg("starting MCP wrapper")

	// Run blocks until the child MCP server process exits.
	return wrapper.Run()
}

func init() {
	proxyWrapMCPCmd.Flags().String("skill-id", "", "skill identifier for decision log entries")
}
