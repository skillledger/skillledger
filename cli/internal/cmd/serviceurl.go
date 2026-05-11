package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

const defaultServiceURL = "https://api.skillledger.in"

// resolveServiceURL returns the effective service URL using precedence:
// explicit --service-url flag > SKILLLEDGER_SERVICE_URL env var > built-in default.
// Per D-20: self-hosters set the env var once and forget the flag.
func resolveServiceURL(cmd *cobra.Command, flagName string) string {
	// If flag was explicitly set by the user, it wins
	if cmd.Flags().Changed(flagName) {
		val, _ := cmd.Flags().GetString(flagName)
		return val
	}
	// Check env var
	if envURL := os.Getenv("SKILLLEDGER_SERVICE_URL"); envURL != "" {
		return envURL
	}
	// Return the flag's default value (which is defaultServiceURL)
	val, _ := cmd.Flags().GetString(flagName)
	return val
}
