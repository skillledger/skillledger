package cmd

import (
	"github.com/spf13/cobra"
)

var proxyUninstallMCPCmd = &cobra.Command{
	Use:   "uninstall-mcp",
	Short: "Restore original MCP client configuration",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Implemented in Task 2.
		return nil
	},
}
