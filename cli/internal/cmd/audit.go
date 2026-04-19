package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"

	"github.com/skillledger/skillledger/internal/ecosystem"
	"github.com/skillledger/skillledger/internal/ioc"
	"github.com/skillledger/skillledger/internal/report"
	"github.com/skillledger/skillledger/internal/sbom"
	"github.com/skillledger/skillledger/internal/scanner"
	yaraengine "github.com/skillledger/skillledger/internal/yara"
)

// OsFileOpener implements scanner.FileOpener using the real filesystem.
type OsFileOpener struct{}

// Open opens a file from the real filesystem.
func (o *OsFileOpener) Open(path string) (io.ReadCloser, error) {
	return os.Open(path)
}

// lipgloss styles for text output
var (
	cleanStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("2"))          // green
	compStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("1")).Bold(true) // red bold
	suspStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("3"))          // yellow
	headerStyle = lipgloss.NewStyle().Bold(true).Underline(true)
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Scan installed skills for known-compromised artifacts and suspicious patterns",
	Long: `Discovers installed AI agent skills across all supported ecosystems,
hashes their contents, checks against the IOC database of known-compromised
artifacts, and optionally runs YARA rules for pattern detection.

Supports multiple output formats: human-readable text (default), JSON,
SARIF (for GitHub Code Scanning), and CycloneDX SBOM.`,
	RunE: runAudit,
}

func runAudit(cmd *cobra.Command, args []string) error {
	format, _ := cmd.Flags().GetString("format")
	outputFile, _ := cmd.Flags().GetString("output")
	liveIOC, _ := cmd.Flags().GetBool("live-ioc")
	yaraRulesDir, _ := cmd.Flags().GetString("yara-rules")
	iocAPIURL, _ := cmd.Flags().GetString("ioc-api-url")

	// Validate format flag
	validFormats := map[string]bool{"text": true, "json": true, "sarif": true, "cyclonedx": true}
	if !validFormats[format] {
		return fmt.Errorf("invalid format %q: must be one of text, json, sarif, cyclonedx", format)
	}

	// Step 1: Load IOC database
	iocDB, err := ioc.Load()
	if err != nil {
		return fmt.Errorf("loading IOC database: %w", err)
	}

	if liveIOC {
		if err := iocDB.FetchUpdates(iocAPIURL); err != nil {
			// Log warning and continue with bundled data (do NOT return error)
			log.Warn().Err(err).Msg("Failed to fetch live IOC updates, using bundled data")
		}
	}

	log.Debug().Int("entries", iocDB.Count()).Msg("IOC database loaded")

	// Step 2: Initialize YARA engine (if --yara-rules provided)
	var yaraEngine *yaraengine.Engine
	if yaraRulesDir != "" {
		yaraEngine, err = yaraengine.NewEngine(yaraRulesDir)
		if err != nil {
			return fmt.Errorf("compiling YARA rules: %w", err)
		}
		log.Debug().Str("dir", yaraRulesDir).Msg("YARA rules compiled")
	}

	// Step 3: Discover installed skills
	fs := afero.NewOsFs()
	skills, err := ecosystem.DefaultRegistry().DiscoverAll(fs)
	if err != nil {
		return fmt.Errorf("discovering skills: %w", err)
	}

	// Count unique ecosystems
	ecosystems := make(map[string]bool)
	for _, s := range skills {
		ecosystems[s.Kind] = true
	}
	log.Info().Int("skills", len(skills)).Int("ecosystems", len(ecosystems)).Msg("Discovery complete")

	if len(skills) == 0 {
		fmt.Fprintln(os.Stdout, "No skills found. Install skills or run from a directory with agent configurations.")
		return nil
	}

	// Step 4: Scan discovered skills
	var scanOpts []scanner.Option
	scanOpts = append(scanOpts, scanner.WithIOC(iocDB))
	if yaraEngine != nil {
		scanOpts = append(scanOpts, scanner.WithYARA(yaraEngine))
	}

	opener := &OsFileOpener{}
	results, err := scanner.NewScanner(opener, scanOpts...).Scan(skills)
	if err != nil {
		return fmt.Errorf("scanning skills: %w", err)
	}

	// Step 5: Output results
	var w io.Writer = os.Stdout
	var outFile *os.File

	if outputFile != "" {
		// Security: validate output path stays within cwd (T-02-09)
		absPath, err := filepath.Abs(outputFile)
		if err != nil {
			return fmt.Errorf("resolving output path: %w", err)
		}
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("getting working directory: %w", err)
		}
		if !strings.HasPrefix(absPath, cwd) {
			return fmt.Errorf("output path escapes working directory")
		}

		outFile, err = os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer outFile.Close()
		w = outFile
	}

	switch format {
	case "text":
		writeTextOutput(w, results)
	case "json":
		if err := report.GenerateJSON(w, results); err != nil {
			return fmt.Errorf("generating JSON output: %w", err)
		}
	case "sarif":
		if err := report.GenerateSARIF(w, results); err != nil {
			return fmt.Errorf("generating SARIF output: %w", err)
		}
	case "cyclonedx":
		if err := sbom.GenerateCycloneDX(w, results); err != nil {
			return fmt.Errorf("generating CycloneDX output: %w", err)
		}
	}

	if outFile != nil {
		fmt.Fprintf(os.Stderr, "Results written to %s\n", outputFile)
	}

	return nil
}

// writeTextOutput renders human-readable audit results with lipgloss styling.
func writeTextOutput(w io.Writer, results []scanner.ScanResult) {
	var clean, compromised, suspicious int

	for _, r := range results {
		var statusStr string
		switch r.Status {
		case "clean":
			statusStr = cleanStyle.Render("CLEAN")
			clean++
		case "compromised":
			statusStr = compStyle.Render("COMPROMISED")
			compromised++
		case "suspicious":
			statusStr = suspStyle.Render("SUSPICIOUS")
			suspicious++
		default:
			statusStr = r.Status
		}

		fmt.Fprintf(w, "[%s] %s (%s) - %s\n", statusStr, r.Skill.Name, r.Skill.Kind, r.Skill.Path)
		fmt.Fprintf(w, "  SHA-256: %s\n", r.SHA256)

		if r.IOCMatch != nil {
			fmt.Fprintf(w, "  IOC: %s (%s)\n", r.IOCMatch.Description, r.IOCMatch.Severity)
		}

		if len(r.YARAMatches) > 0 {
			ruleNames := make([]string, 0, len(r.YARAMatches))
			for _, ym := range r.YARAMatches {
				ruleNames = append(ruleNames, ym.RuleName)
			}
			fmt.Fprintf(w, "  YARA: %s\n", strings.Join(ruleNames, ", "))
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintf(w, "%s: %d skills scanned, %d clean, %d compromised, %d suspicious\n",
		headerStyle.Render("Summary"),
		len(results), clean, compromised, suspicious)
}

func init() {
	auditCmd.Flags().StringP("format", "f", "text", "output format: text, json, sarif, cyclonedx")
	auditCmd.Flags().StringP("output", "o", "", "write output to file instead of stdout")
	auditCmd.Flags().Bool("live-ioc", false, "fetch latest IOC list from SkillLedger API")
	auditCmd.Flags().String("yara-rules", "", "path to directory of .yar rule files")
	auditCmd.Flags().String("ioc-api-url", "https://api.skillledger.dev/v1/ioc", "IOC API endpoint URL")
	_ = auditCmd.Flags().MarkHidden("ioc-api-url")
	rootCmd.AddCommand(auditCmd)
}
