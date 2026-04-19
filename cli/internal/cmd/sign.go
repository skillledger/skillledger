package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/charmbracelet/lipgloss"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/skillledger/skillledger/internal/builder"
	"github.com/skillledger/skillledger/internal/signer"
)

// lipgloss styles for sign command output.
var (
	signSuccessStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("2")).Bold(true) // green bold
	signInfoStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("6"))            // cyan
	signWarnStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("3"))            // yellow
)

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign a built artifact with Sigstore keyless signing and SLSA provenance",
	Long: `Signs a previously built skill artifact using Sigstore keyless signing.
Authenticates via OIDC (set SIGSTORE_ID_TOKEN env var or use --identity-token),
generates an Ed25519 ephemeral keypair, obtains a Fulcio certificate, and records
the signing event in the Rekor transparency log.

The command creates a .sigstore.json bundle alongside the artifact and updates
the skill-lock.json with provenance and log entry references.

Requires a prior 'skillledger build' to have produced the artifact and lockfile.`,
	RunE: runSign,
}

func runSign(cmd *cobra.Command, args []string) error {
	artifactPath, _ := cmd.Flags().GetString("artifact")
	lockfilePath, _ := cmd.Flags().GetString("lockfile")
	identityToken, _ := cmd.Flags().GetString("identity-token")

	// Resolve artifact path
	absArtifact, err := filepath.Abs(artifactPath)
	if err != nil {
		return fmt.Errorf("resolving artifact path: %w", err)
	}

	// T-04-10: Verify artifact exists before proceeding
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

	log.Info().Str("artifact", absArtifact).Str("lockfile", absLockfile).Msg("Starting signing")

	// Step 1: Read lockfile
	lf, err := builder.ReadLockfile(absLockfile)
	if err != nil {
		return fmt.Errorf("reading lockfile: %w", err)
	}
	sha256Display := lf.SHA256
	if len(sha256Display) > 12 {
		sha256Display = sha256Display[:12]
	}
	log.Debug().Str("artifact_id", lf.ArtifactID).Str("sha256", sha256Display).Msg("Lockfile loaded")

	// Step 2: Create provenance
	stmt, err := signer.CreateProvenance(signer.ProvenanceInput{
		ArtifactName:   lf.ContentAddress,
		ArtifactDigest: lf.SHA256,
		Repository:     lf.Source.Repository,
		Ref:            lf.Source.Ref,
		Directory:      lf.Source.Directory,
		BuiltAt:        lf.BuiltAt,
		BuilderVersion: "0.1.0",
	})
	if err != nil {
		return fmt.Errorf("creating provenance: %w", err)
	}
	log.Debug().Msg("SLSA provenance statement created")

	// Step 3: Sign with Sigstore
	opts := []signer.Option{}
	if identityToken != "" {
		opts = append(opts, signer.WithIdentityToken(identityToken))
	}
	s := signer.NewSigner(opts...)
	result, err := s.SignAndWrite(stmt, absArtifact)
	if err != nil {
		return fmt.Errorf("signing failed: %w", err)
	}
	log.Debug().Str("bundle", result.BundlePath).Int64("log_index", result.LogIndex).Msg("Artifact signed")

	// Step 4: Update lockfile with provenance and log entry (T-04-11: JCS canonicalization via WriteLockfile)
	lf.Provenance = result.BundlePath
	lf.LogEntryID = fmt.Sprintf("%d", result.LogIndex)
	if err := builder.WriteLockfile(absLockfile, lf); err != nil {
		return fmt.Errorf("updating lockfile: %w", err)
	}

	// Step 5: Display success output
	fmt.Fprintln(os.Stdout)
	fmt.Fprintf(os.Stdout, "%s\n\n", signSuccessStyle.Render("Signing successful"))
	fmt.Fprintf(os.Stdout, "  %s  %s\n", signInfoStyle.Render("Bundle:"), result.BundlePath)
	fmt.Fprintf(os.Stdout, "  %s  %d\n", signInfoStyle.Render("Log Index:"), result.LogIndex)
	fmt.Fprintf(os.Stdout, "  %s  %s\n", signInfoStyle.Render("Lockfile:"), absLockfile)
	fmt.Fprintln(os.Stdout)

	return nil
}

func init() {
	signCmd.Flags().StringP("artifact", "a", "", "path to the built .skillledger.tar.gz artifact (required)")
	signCmd.Flags().StringP("lockfile", "l", "", "path to skill-lock.json (default: auto-detect from artifact location)")
	signCmd.Flags().String("identity-token", "", "OIDC identity token (or set SIGSTORE_ID_TOKEN env var)")
	_ = signCmd.MarkFlagRequired("artifact")
	rootCmd.AddCommand(signCmd)
}
