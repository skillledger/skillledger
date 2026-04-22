package cmd

import (
	"fmt"

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

	wrapper, err := proxy.NewMCPWrapper(command, cmdArgs, skillID, dl, log.Logger)
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
