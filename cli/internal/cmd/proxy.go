package cmd

import (
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Runtime proxy for intercepting skill I/O",
	Long: `HTTP/HTTPS MITM proxy and MCP stdio interceptor for runtime skill traffic
inspection. The proxy intercepts outbound network requests from skills and
MCP JSON-RPC messages, logging every decision for post-hoc review.

Subcommands let you start/stop the proxy, inspect decisions, manage the CA
trust store, and configure MCP clients to route through the proxy wrapper.`,
}

// proxyBaseDir returns the SkillLedger home directory.
// Uses SKILLLEDGER_HOME env var if set, otherwise ~/.skillledger.
func proxyBaseDir() string {
	if dir := os.Getenv("SKILLLEDGER_HOME"); dir != "" {
		return dir
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", ".skillledger")
	}
	return filepath.Join(home, ".skillledger")
}

func init() {
	proxyCmd.AddCommand(proxyStartCmd)
	proxyCmd.AddCommand(proxyStopCmd)
	proxyCmd.AddCommand(proxyStatusCmd)
	proxyCmd.AddCommand(proxyExplainCmd)
	proxyCmd.AddCommand(proxyTrustCmd)
	proxyCmd.AddCommand(proxyInstallMCPCmd)
	proxyCmd.AddCommand(proxyUninstallMCPCmd)
	proxyCmd.AddCommand(proxyWrapMCPCmd)
	rootCmd.AddCommand(proxyCmd)
}
