package cmd

import (
	"github.com/spf13/cobra"
)

var proxyExplainCmd = &cobra.Command{
	Use:   "explain [action-id]",
	Short: "Explain a proxy decision",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// Implemented in Task 2.
		return nil
	},
}
