package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/skillledger/skillledger/internal/proxy"
	"github.com/skillledger/skillledger/internal/report"
)

var proxyReportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate violation report from proxy session",
	Long: `Generates a report from the proxy decision log, including only entries
with scanner findings. Supports SARIF (default) and JSON output formats.

The SARIF output is compatible with GitHub Code Scanning upload.`,
	RunE: runProxyReport,
}

func runProxyReport(cmd *cobra.Command, args []string) error {
	format, _ := cmd.Flags().GetString("format")
	outputPath, _ := cmd.Flags().GetString("output")

	logPath := filepath.Join(proxyBaseDir(), "proxy", "decisions.jsonl")

	// Read all decision entries from JSONL.
	entries, err := readDecisionEntries(logPath)
	if err != nil {
		return fmt.Errorf("reading decision log: %w", err)
	}

	// Filter to entries with findings only.
	var withFindings []proxy.DecisionEntry
	for _, e := range entries {
		if len(e.Findings) > 0 {
			withFindings = append(withFindings, e)
		}
	}

	// Determine output writer.
	var w *os.File
	if outputPath != "" {
		w, err = os.Create(outputPath)
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer w.Close()
	} else {
		w = os.Stdout
	}

	switch format {
	case "sarif":
		return report.GenerateRuntimeSARIF(w, withFindings)
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(withFindings)
	default:
		return fmt.Errorf("unsupported format %q (use sarif or json)", format)
	}
}

// readDecisionEntries reads all DecisionEntry records from a JSONL file.
func readDecisionEntries(path string) ([]proxy.DecisionEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []proxy.DecisionEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var entry proxy.DecisionEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			continue // skip malformed lines
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		return entries, err
	}
	return entries, nil
}

func init() {
	proxyReportCmd.Flags().StringP("format", "", "sarif", "output format (sarif or json)")
	proxyReportCmd.Flags().StringP("output", "o", "", "output file path (default: stdout)")
}
