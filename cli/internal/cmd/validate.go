package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/skillledger/skillledger/internal/manifest"
	"github.com/skillledger/skillledger/internal/output"
)

var validateCmd = &cobra.Command{
	Use:   "validate [file]",
	Short: "Validate a skillledger.yaml manifest against the schema",
	Long:  "Validates a skillledger.yaml manifest file against the SkillLedger artifact spec JSON Schema.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0]

		// Security: limit file size to 1MB (T-01-02)
		info, err := os.Stat(filePath)
		if err != nil {
			return fmt.Errorf("reading manifest: %w", err)
		}
		if info.Size() > 1<<20 {
			return fmt.Errorf("manifest file too large: %d bytes (max 1MB)", info.Size())
		}

		data, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("reading manifest: %w", err)
		}

		m, validationErrors, err := manifest.ParseAndValidate(data)
		if err != nil {
			return fmt.Errorf("parsing manifest: %w", err)
		}

		result := &output.ValidationResult{
			File: filePath,
		}

		if len(validationErrors) > 0 {
			result.Valid = false
			for _, ve := range validationErrors {
				result.Errors = append(result.Errors, output.ValidationErr{
					Path:    ve.Path,
					Message: ve.Message,
				})
			}
		} else {
			result.Valid = true
			result.Kind = m.Kind
		}

		return output.PrintValidationResult(os.Stdout, result, jsonOutput)
	},
}

func init() {
	rootCmd.AddCommand(validateCmd)
}
