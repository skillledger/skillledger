package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/skillledger/skillledger/internal/output"
	"github.com/skillledger/skillledger/internal/proxy"
)

var proxyLogsCmd = &cobra.Command{
	Use:   "logs",
	Short: "View proxy decision log",
	Long: `Displays the proxy decision log from decisions.jsonl with human-readable formatting.

Supports filtering by severity, skill, scanner, and time range.
Use --follow to live-tail the log file for new entries.
Use --json to output raw JSONL for piping to jq.`,
	RunE: runProxyLogs,
}

func runProxyLogs(cmd *cobra.Command, args []string) error {
	jsonMode, _ := cmd.Flags().GetBool("json")
	follow, _ := cmd.Flags().GetBool("follow")
	severityFlag, _ := cmd.Flags().GetString("severity")
	skillFilter, _ := cmd.Flags().GetString("skill")
	scannerFilter, _ := cmd.Flags().GetString("scanner")
	sinceFlag, _ := cmd.Flags().GetString("since")

	logPath := filepath.Join(proxyBaseDir(), "proxy", "decisions.jsonl")

	// Parse --since duration.
	var sinceTime time.Time
	if sinceFlag != "" {
		dur, err := time.ParseDuration(sinceFlag)
		if err != nil {
			return fmt.Errorf("invalid --since duration %q: %w", sinceFlag, err)
		}
		sinceTime = time.Now().Add(-dur)
	}

	// Parse --severity into a set of ActionTypes.
	severitySet := make(map[proxy.ActionType]bool)
	if severityFlag != "" {
		for _, s := range strings.Split(severityFlag, ",") {
			s = strings.TrimSpace(s)
			severitySet[proxy.ActionType(s)] = true
		}
	}

	// Build filter function.
	filter := func(entry proxy.DecisionEntry) bool {
		if len(severitySet) > 0 && !severitySet[entry.Decision] {
			return false
		}
		if skillFilter != "" && entry.SkillID != skillFilter {
			return false
		}
		if scannerFilter != "" {
			found := false
			for _, f := range entry.Findings {
				if f.Scanner == scannerFilter {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
		if !sinceTime.IsZero() && entry.Timestamp.Before(sinceTime) {
			return false
		}
		return true
	}

	// Determine color support.
	useColor := os.Getenv("NO_COLOR") == "" && !jsonMode

	if follow {
		return tailLog(logPath, filter, jsonMode, useColor)
	}
	return readLog(logPath, filter, jsonMode, useColor)
}

// readLog reads the entire decisions.jsonl and prints matching entries.
func readLog(path string, filter func(proxy.DecisionEntry) bool, jsonMode, useColor bool) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening decision log: %w", err)
	}
	defer f.Close()

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
		if !filter(entry) {
			continue
		}
		printEntry(entry, line, jsonMode, useColor)
	}
	return scanner.Err()
}

// tailLog opens the file, seeks to end, and polls for new lines.
func tailLog(path string, filter func(proxy.DecisionEntry) bool, jsonMode, useColor bool) error {
	f, err := os.Open(path)
	if err != nil {
		// If file doesn't exist yet, create it and wait.
		if os.IsNotExist(err) {
			// Ensure directory exists.
			dir := filepath.Dir(path)
			if mkErr := os.MkdirAll(dir, 0700); mkErr != nil {
				return fmt.Errorf("creating log directory: %w", mkErr)
			}
			f, err = os.Create(path)
			if err != nil {
				return fmt.Errorf("creating decision log: %w", err)
			}
		} else {
			return fmt.Errorf("opening decision log: %w", err)
		}
	}
	defer f.Close()

	// Seek to end.
	if _, err := f.Seek(0, 2); err != nil {
		return fmt.Errorf("seeking to end: %w", err)
	}

	// Listen for SIGINT to exit cleanly.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	scanner := bufio.NewScanner(f)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-sigCh:
			return nil
		case <-ticker.C:
			for scanner.Scan() {
				line := scanner.Bytes()
				if len(line) == 0 {
					continue
				}
				var entry proxy.DecisionEntry
				if err := json.Unmarshal(line, &entry); err != nil {
					continue
				}
				if !filter(entry) {
					continue
				}
				printEntry(entry, line, jsonMode, useColor)
			}
			if err := scanner.Err(); err != nil {
				return fmt.Errorf("reading log: %w", err)
			}
		}
	}
}

// printEntry prints a single entry in the appropriate format.
func printEntry(entry proxy.DecisionEntry, raw []byte, jsonMode, useColor bool) {
	if jsonMode {
		fmt.Println(string(raw))
	} else {
		fmt.Println(output.FormatLogEntry(entry, useColor))
	}
}

func init() {
	proxyLogsCmd.Flags().Bool("json", false, "output raw JSONL for piping to jq")
	proxyLogsCmd.Flags().BoolP("follow", "f", false, "live tail mode")
	proxyLogsCmd.Flags().String("severity", "", "filter by decision (allow,warn,block,log)")
	proxyLogsCmd.Flags().String("skill", "", "filter by skill ID")
	proxyLogsCmd.Flags().String("scanner", "", "filter by scanner name (secret,network,injection,capability,pinchange,yara)")
	proxyLogsCmd.Flags().String("since", "", "duration filter (e.g., 30m, 2h)")
}
