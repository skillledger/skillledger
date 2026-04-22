package cmd

import (
	"github.com/spf13/cobra"
)

var proxyInstallMCPCmd = &cobra.Command{
	Use:   "install-mcp",
	Short: "Configure MCP clients to use the proxy",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Implemented in Task 2.
		return nil
	},
}
