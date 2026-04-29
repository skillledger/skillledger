package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/charmbracelet/lipgloss"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/spf13/afero"

	"github.com/skillledger/skillledger/internal/builder"
	"github.com/skillledger/skillledger/internal/tlog"
)

// lipgloss styles for publish command output.
var (
	publishSuccessStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("2")).Bold(true) // green bold
	publishInfoStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("6"))            // cyan
	publishWarnStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("3"))            // yellow
)

var publishCmd = &cobra.Command{
	Use:   "publish",
	Short: "Publish a signed artifact to the transparency log",
	Long: `Publishes a previously signed skill artifact to the SkillLedger transparency log.
The command reads the lockfile to extract artifact metadata, submits an entry
to the log service, and updates the lockfile with the log entry ID.

Requires a prior 'skillledger build' and 'skillledger sign' to have produced
the artifact, lockfile, and signing bundle.`,
	RunE: runPublish,
}

func runPublish(cmd *cobra.Command, args []string) error {
	artifactPath, _ := cmd.Flags().GetString("artifact")
	lockfilePath, _ := cmd.Flags().GetString("lockfile")
	serviceURL := resolveServiceURL(cmd, "service-url")
	publisher, _ := cmd.Flags().GetString("publisher")
	apiKey, _ := cmd.Flags().GetString("api-key")
	if apiKey == "" {
		apiKey = os.Getenv("SKILLLEDGER_API_KEY")
	}

	// Resolve artifact path
	absArtifact, err := filepath.Abs(artifactPath)
	if err != nil {
		return fmt.Errorf("resolving artifact path: %w", err)
	}

	// Verify artifact exists
	if _, err := os.Stat(absArtifact); err != nil {
		return fmt.Errorf("artifact not found: %w", err)
	}

	// Resolve lockfile path (default: skill-lock.json in artifact's parent's parent dir,
	// matching build output layout where artifact is in source/dist/ and lockfile is in source/)
	if lockfilePath == "" {
		lockfilePath = filepath.Join(filepath.Dir(filepath.Dir(absArtifact)), "skill-lock.json")
	}
	absLockfile, err := filepath.Abs(lockfilePath)
	if err != nil {
		return fmt.Errorf("resolving lockfile path: %w", err)
	}

	log.Info().Str("artifact", absArtifact).Str("lockfile", absLockfile).Msg("Starting publish")

	// Step 1: Read lockfile
	osFs := afero.NewOsFs()
	lf, err := builder.ReadLockfile(osFs, absLockfile)
	if err != nil {
		return fmt.Errorf("reading lockfile: %w", err)
	}
	log.Debug().Str("artifact_id", lf.ArtifactID).Msg("Lockfile loaded")

	// Step 2: Verify artifact has been signed (T-05-18: provenance check before publish)
	if lf.Provenance == "" {
		return fmt.Errorf("artifact must be signed before publishing (run 'skillledger sign' first)")
	}

	// Step 3: Publish to transparency log
	result, err := tlog.Publish(context.Background(), tlog.PublishInput{
		ArtifactID:     lf.ArtifactID,
		SHA256:         lf.SHA256,
		ContentAddress: lf.ContentAddress,
		Publisher:      publisher,
		ServiceURL:     serviceURL,
		APIKey:         apiKey,
	})
	if err != nil {
		return fmt.Errorf("publish failed: %w", err)
	}
	log.Debug().Int64("log_index", result.LogIndex).Msg("Published to transparency log")

	// Step 4: Update lockfile with log entry ID (T-05-17: local record of publish)
	lf.LogEntryID = fmt.Sprintf("%d", result.LogIndex)
	if err := builder.WriteLockfile(osFs, absLockfile, lf); err != nil {
		return fmt.Errorf("updating lockfile: %w", err)
	}

	// Step 5: Display success output
	fmt.Fprintln(os.Stdout)
	fmt.Fprintf(os.Stdout, "%s\n\n", publishSuccessStyle.Render("Published to transparency log"))
	fmt.Fprintf(os.Stdout, "  %s  %d\n", publishInfoStyle.Render("Log Index:"), result.LogIndex)
	fmt.Fprintf(os.Stdout, "  %s  %s\n", publishInfoStyle.Render("Artifact:"), lf.ArtifactID)
	fmt.Fprintf(os.Stdout, "  %s  %s\n", publishInfoStyle.Render("Lockfile:"), absLockfile)
	fmt.Fprintln(os.Stdout)

	return nil
}

func init() {
	publishCmd.Flags().StringP("artifact", "a", "", "path to the built .skillledger.tar.gz artifact (required)")
	publishCmd.Flags().StringP("lockfile", "l", "", "path to skill-lock.json (default: auto-detect from artifact location)")
	publishCmd.Flags().String("service-url", defaultServiceURL, "SkillLedger service URL")
	publishCmd.Flags().StringP("publisher", "p", "", "publisher identity (OIDC email or identity, required)")
	publishCmd.Flags().String("api-key", "", "API key for authenticated publish (or set SKILLLEDGER_API_KEY env var)")
	_ = publishCmd.MarkFlagRequired("artifact")
	_ = publishCmd.MarkFlagRequired("publisher")
	rootCmd.AddCommand(publishCmd)
}
