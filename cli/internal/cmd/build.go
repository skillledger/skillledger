package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/charmbracelet/lipgloss"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/skillledger/skillledger/internal/builder"
)

// lipgloss styles for build command output.
var (
	buildSuccessStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("2")).Bold(true) // green bold
	buildInfoStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("6"))            // cyan
)

var buildCmd = &cobra.Command{
	Use:   "build",
	Short: "Build a deterministic, content-addressed artifact from a skill source tree",
	Long: `Reads a skillledger.yaml manifest from the source directory, collects all
source files (respecting .skillledgerignore), and packages them into a
deterministic, content-addressed .skillledger.tar.gz artifact.

The build produces identical output for identical input: file ordering is
lexicographic, timestamps are clamped to SOURCE_DATE_EPOCH, and all filesystem
metadata is normalized.

A skill-lock.json lockfile is generated alongside the manifest containing the
artifact hash and provenance reference.`,
	RunE: runBuild,
}

func runBuild(cmd *cobra.Command, args []string) error {
	sourceDir, _ := cmd.Flags().GetString("source-dir")
	outputDir, _ := cmd.Flags().GetString("output")

	abs, err := filepath.Abs(sourceDir)
	if err != nil {
		return fmt.Errorf("resolving source directory: %w", err)
	}

	log.Info().Str("source", abs).Str("output", outputDir).Msg("Starting build")

	b := builder.NewBuilder()
	result, err := b.Build(abs, outputDir)
	if err != nil {
		return fmt.Errorf("build failed: %w", err)
	}

	fmt.Fprintln(os.Stdout)
	fmt.Fprintf(os.Stdout, "%s\n\n", buildSuccessStyle.Render("Build successful"))
	fmt.Fprintf(os.Stdout, "  %s  %s\n", buildInfoStyle.Render("Artifact:"), result.ArtifactPath)
	fmt.Fprintf(os.Stdout, "  %s  %s\n", buildInfoStyle.Render("SHA-256:"), result.SHA256)
	fmt.Fprintf(os.Stdout, "  %s  %s\n", buildInfoStyle.Render("Lockfile:"), result.LockfilePath)
	fmt.Fprintln(os.Stdout)

	return nil
}

func init() {
	buildCmd.Flags().StringP("source-dir", "s", ".", "path to skill source directory containing skillledger.yaml")
	buildCmd.Flags().StringP("output", "o", "./dist", "directory to write the built artifact")
	rootCmd.AddCommand(buildCmd)
}
