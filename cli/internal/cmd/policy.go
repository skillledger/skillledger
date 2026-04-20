package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/skillledger/skillledger/internal/manifest"
	"github.com/skillledger/skillledger/internal/output"
	"github.com/skillledger/skillledger/internal/policy"
	"github.com/skillledger/skillledger/internal/policy/dsl"
	"github.com/skillledger/skillledger/internal/policy/eval"
)

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage and evaluate capability policies",
	Long:  "Define, compile, and evaluate capability policies that govern what skills are allowed to do.",
}

var policyCheckCmd = &cobra.Command{
	Use:   "check [manifest]",
	Short: "Check a manifest against a capability policy",
	Long: `Evaluates a skill manifest's capabilities against a preset or custom policy
and returns allow/deny/warn. Use --preset for built-in policies or --policy-file
for custom DSL policies. Use --issuer to provide OIDC issuer for allowlist matching.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		manifestPath := args[0]
		presetName, _ := cmd.Flags().GetString("preset")
		policyFile, _ := cmd.Flags().GetString("policy-file")
		issuer, _ := cmd.Flags().GetString("issuer")

		// Validate: exactly one of --preset or --policy-file must be set
		if presetName == "" && policyFile == "" {
			return fmt.Errorf("specify --preset or --policy-file")
		}
		if presetName != "" && policyFile != "" {
			return fmt.Errorf("specify only one of --preset or --policy-file, not both")
		}

		// Security: limit manifest file size to 1MB (T-06-11)
		info, err := os.Stat(manifestPath)
		if err != nil {
			return fmt.Errorf("reading manifest: %w", err)
		}
		if info.Size() > 1<<20 {
			return fmt.Errorf("manifest file too large: %d bytes (max 1MB)", info.Size())
		}

		// Parse manifest
		data, err := os.ReadFile(manifestPath)
		if err != nil {
			return fmt.Errorf("reading manifest: %w", err)
		}
		m, _, err := manifest.ParseAndValidate(data)
		if err != nil {
			return fmt.Errorf("parsing manifest: %w", err)
		}

		// Load policy evaluator
		var evaluator *eval.Evaluator
		var policyLabel string
		if presetName != "" {
			evaluator, err = policy.LoadPreset(presetName)
			policyLabel = presetName
		} else {
			// Security: limit policy file size to 1MB (T-06-11)
			pInfo, pErr := os.Stat(policyFile)
			if pErr != nil {
				return fmt.Errorf("reading policy file: %w", pErr)
			}
			if pInfo.Size() > 1<<20 {
				return fmt.Errorf("policy file too large: %d bytes (max 1MB)", pInfo.Size())
			}
			evaluator, err = policy.LoadPolicyFile(policyFile)
			policyLabel = "custom"
		}
		if err != nil {
			return fmt.Errorf("loading policy: %w", err)
		}

		log.Debug().Str("manifest", manifestPath).Str("policy", policyLabel).Msg("evaluating policy")

		// Build PolicyInput with explicit issuer for allowlist matching.
		// Uses EvaluateInput (NOT EvaluateManifest) so that --issuer flag
		// value reaches OPA for PLCY-04 allowlist cert-identity+issuer matching.
		pi := policy.PolicyInput{
			Capabilities: m.Capabilities,
		}
		if m.Attestation != nil {
			pi.SignedBy = m.Attestation.SignedBy
		}
		// --issuer flag provides the OIDC issuer for allowlist matching.
		// In future phases, this could be derived from Sigstore verification.
		pi.Issuer = issuer

		ctx := context.Background()
		result, err := policy.EvaluateInput(ctx, evaluator, pi)
		if err != nil {
			return fmt.Errorf("evaluating policy: %w", err)
		}

		// Output
		checkResult := &output.PolicyCheckResult{
			File:       manifestPath,
			Policy:     policyLabel,
			Decision:   result.Decision,
			Violations: result.Violations,
			Warnings:   result.Warnings,
		}
		if err := output.PrintPolicyResult(os.Stdout, checkResult, jsonOutput); err != nil {
			return err
		}

		// Return error for deny decision so Cobra can handle cleanup.
		// The root command's Execute function should translate this to exit code 1.
		if result.Decision == "deny" {
			return fmt.Errorf("policy denied")
		}
		return nil
	},
}

var policyCompileCmd = &cobra.Command{
	Use:   "compile [policy-file]",
	Short: "Compile a DSL policy file to Rego",
	Long:  "Parses a YAML DSL policy file and outputs the compiled Rego source code.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		policyFile := args[0]

		// Security: limit file size to 1MB (T-06-11)
		info, err := os.Stat(policyFile)
		if err != nil {
			return fmt.Errorf("reading policy file: %w", err)
		}
		if info.Size() > 1<<20 {
			return fmt.Errorf("policy file too large: %d bytes (max 1MB)", info.Size())
		}

		data, err := os.ReadFile(policyFile)
		if err != nil {
			return fmt.Errorf("reading policy file: %w", err)
		}

		p, err := dsl.Parse(data)
		if err != nil {
			return fmt.Errorf("parsing policy: %w", err)
		}

		rego, err := dsl.Compile(p)
		if err != nil {
			return fmt.Errorf("compiling policy: %w", err)
		}

		return output.PrintCompileResult(os.Stdout, rego, jsonOutput)
	},
}

var policyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available preset policies",
	RunE: func(cmd *cobra.Command, args []string) error {
		presets := policy.ListPresets()
		return output.PrintPresetList(os.Stdout, presets, jsonOutput)
	},
}

func init() {
	policyCheckCmd.Flags().StringP("preset", "p", "", "preset policy name: strict, moderate, permissive")
	policyCheckCmd.Flags().StringP("policy-file", "f", "", "path to DSL policy YAML file")
	policyCheckCmd.Flags().String("issuer", "", "OIDC issuer URL for publisher allowlist matching (e.g., https://accounts.google.com)")

	policyCmd.AddCommand(policyCheckCmd)
	policyCmd.AddCommand(policyCompileCmd)
	policyCmd.AddCommand(policyListCmd)
	rootCmd.AddCommand(policyCmd)
}
