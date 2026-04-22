package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/skillledger/skillledger/internal/proxy"
)

var proxyExplainCmd = &cobra.Command{
	Use:   "explain [action-id]",
	Short: "Explain a proxy decision",
	Long: `Looks up a proxy decision by its action ID and displays a detailed
explanation. The decision log is stored at ~/.skillledger/proxy/decisions.jsonl
and is written by the running proxy process.

Use --json for machine-readable output.`,
	Args: cobra.ExactArgs(1),
	RunE: runProxyExplain,
}

func runProxyExplain(cmd *cobra.Command, args []string) error {
	actionID := args[0]
	baseDir := proxyBaseDir()
	logPath := filepath.Join(baseDir, "proxy", "decisions.jsonl")

	f, err := os.Open(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("no decision log found at %s -- is the proxy running?", logPath)
		}
		return fmt.Errorf("opening decision log: %w", err)
	}
	defer f.Close()

	// Scan the JSONL file for the matching action ID.
	scanner := bufio.NewScanner(f)
	// Allow up to 1MB per line for safety.
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	var found *proxy.DecisionEntry
	for scanner.Scan() {
		var entry proxy.DecisionEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue // skip malformed lines
		}
		if entry.ActionID == actionID {
			found = &entry
			// Don't break -- keep scanning for the latest entry with this ID.
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("reading decision log: %w", err)
	}

	if found == nil {
		return fmt.Errorf("action %s not found in decision log", actionID)
	}

	result := proxy.ExplainResultFromEntry(*found)
	return proxy.FormatExplain(os.Stdout, result, jsonOutput)
}
