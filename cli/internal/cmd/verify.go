package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/charmbracelet/lipgloss"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/skillledger/skillledger/internal/output"
	"github.com/skillledger/skillledger/internal/policy"
	"github.com/skillledger/skillledger/internal/signer"
	"github.com/skillledger/skillledger/internal/tlog"
	"github.com/skillledger/skillledger/internal/verify"
)

// lipgloss styles for verify command output.
var (
	verifySuccessStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("2")).Bold(true) // green bold
	verifyFailedStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("1")).Bold(true) // red bold
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify a skill artifact's signature, provenance, log presence, and policy compliance",
	Long: `Verifies a previously built and signed skill artifact. Checks:
1. Artifact hash matches lockfile (tampering detection)
2. Sigstore signature validity and signer identity
3. Transparency log entry existence and hash match
4. Capability policy compliance (preset or custom)

Fails closed: any check failure blocks the artifact.
Use --skip-tlog for offline verification (signature and policy still enforced).

Exit codes: 0 = pass, 1 = fail (deny or error)`,
	RunE: runVerify,
}

func runVerify(cmd *cobra.Command, args []string) error {
	artifactPath, _ := cmd.Flags().GetString("artifact")
	lockfilePath, _ := cmd.Flags().GetString("lockfile")
	bundlePath, _ := cmd.Flags().GetString("bundle")
	manifestPath, _ := cmd.Flags().GetString("manifest")
	presetName, _ := cmd.Flags().GetString("preset")
	policyFile, _ := cmd.Flags().GetString("policy-file")
	serviceURL, _ := cmd.Flags().GetString("service-url")
	skipTlog, _ := cmd.Flags().GetBool("skip-tlog")
	expectedIssuer, _ := cmd.Flags().GetString("expected-issuer")
	expectedIdentity, _ := cmd.Flags().GetString("expected-identity")

	// Resolve artifact path
	absArtifact, err := filepath.Abs(artifactPath)
	if err != nil {
		return fmt.Errorf("resolving artifact path: %w", err)
	}

	// Verify artifact exists
	if _, err := os.Stat(absArtifact); err != nil {
		return fmt.Errorf("artifact not found: %w", err)
	}

	// Security: check manifest file size limit (1MB) before parsing (T-07-07)
	if manifestPath != "" {
		info, err := os.Stat(manifestPath)
		if err == nil && info.Size() > 1<<20 {
			return fmt.Errorf("manifest file too large: %d bytes (max 1MB)", info.Size())
		}
	}

	log.Info().Str("artifact", absArtifact).Msg("Starting verification")

	// Create signer.Verifier
	var verifierOpts []signer.VerifierOption
	if expectedIssuer != "" && expectedIdentity != "" {
		verifierOpts = append(verifierOpts,
			signer.WithExpectedIssuer(expectedIssuer),
			signer.WithExpectedSAN(expectedIdentity),
		)
	}
	sigVerifier := signer.NewVerifier(verifierOpts...)

	// Create tlog.Client
	tlogClient := tlog.NewClient(tlog.WithServiceURL(serviceURL))

	// Load policy evaluator
	var policyEval verify.PolicyEvaluator
	if policyFile != "" {
		evaluator, err := policy.LoadPolicyFile(policyFile)
		if err != nil {
			return fmt.Errorf("loading policy file: %w", err)
		}
		policyEval = evaluator
	} else {
		evaluator, err := policy.LoadPreset(presetName)
		if err != nil {
			return fmt.Errorf("loading preset policy: %w", err)
		}
		policyEval = evaluator
	}

	// Create verify pipeline
	pipeline := verify.NewPipeline(sigVerifier, tlogClient, policyEval, verify.WithSkipTlog(skipTlog))

	// Build verification input
	input := verify.VerifyInput{
		ArtifactPath: absArtifact,
		BundlePath:   bundlePath,
		LockfilePath: lockfilePath,
		ManifestPath: manifestPath,
		PolicyPreset: presetName,
		PolicyFile:   policyFile,
		SkipTlog:     skipTlog,
	}

	// Run verification
	result, err := pipeline.Verify(context.Background(), input)
	if err != nil {
		return fmt.Errorf("verification error: %w", err)
	}

	log.Info().Bool("passed", result.Passed).Int("steps", len(result.Steps)).Msg("Verification complete")

	// Map verify.VerifyResult to output.VerifyCheckResult
	checkResult := &output.VerifyCheckResult{
		Artifact:   absArtifact,
		Passed:     result.Passed,
		Steps:      make([]output.VerifyStepOutput, len(result.Steps)),
		Violations: result.Violations,
		Warnings:   result.Warnings,
	}
	for i, step := range result.Steps {
		checkResult.Steps[i] = output.VerifyStepOutput{
			Name:   step.Name,
			Passed: step.Passed,
			Detail: step.Detail,
			Error:  step.Error,
		}
	}

	// Print result (T-07-09: only structured step-level errors, no stack traces)
	if err := output.PrintVerifyResult(os.Stdout, checkResult, jsonOutput); err != nil {
		return err
	}

	// T-07-10: fail-closed -- verification failure always returns non-zero exit code
	if !result.Passed {
		return fmt.Errorf("verification failed")
	}

	return nil
}

func init() {
	verifyCmd.Flags().StringP("artifact", "a", "", "path to the .skillledger.tar.gz artifact (required)")
	verifyCmd.Flags().StringP("lockfile", "l", "", "path to skill-lock.json (default: auto-detect)")
	verifyCmd.Flags().StringP("bundle", "b", "", "path to .sigstore.json bundle (default: artifact + .sigstore.json)")
	verifyCmd.Flags().StringP("manifest", "m", "", "path to skillledger.yaml (default: auto-detect)")
	verifyCmd.Flags().StringP("preset", "p", "moderate", "preset policy: strict, moderate, permissive")
	verifyCmd.Flags().StringP("policy-file", "f", "", "custom DSL policy file (overrides --preset)")
	verifyCmd.Flags().String("service-url", "http://localhost:8000", "transparency log service URL")
	verifyCmd.Flags().Bool("skip-tlog", false, "skip transparency log verification (offline mode)")
	verifyCmd.Flags().String("expected-issuer", "", "expected OIDC issuer for identity verification")
	verifyCmd.Flags().String("expected-identity", "", "expected signer identity (SAN)")
	_ = verifyCmd.MarkFlagRequired("artifact")
	rootCmd.AddCommand(verifyCmd)
}
