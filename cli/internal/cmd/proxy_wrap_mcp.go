package cmd

import (
	"github.com/spf13/cobra"
)

var proxyWrapMCPCmd = &cobra.Command{
	Use:    "wrap-mcp",
	Short:  "Internal: wrap an MCP server through the proxy",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Implemented in Task 2.
		return nil
	},
}
