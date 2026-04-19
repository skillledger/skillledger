package output

import (
	"encoding/json"
	"fmt"
	"io"
)

// ValidationResult represents the outcome of validating a manifest.
type ValidationResult struct {
	Valid  bool            `json:"valid"`
	File   string          `json:"file"`
	Kind   string          `json:"kind,omitempty"`
	Errors []ValidationErr `json:"errors,omitempty"`
}

// ValidationErr represents a single validation error for output.
type ValidationErr struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

// PrintValidationResult writes the validation result to w in text or JSON format.
func PrintValidationResult(w io.Writer, result *ValidationResult, jsonMode bool) error {
	if jsonMode {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}
	if result.Valid {
		fmt.Fprintf(w, "VALID: %s (kind: %s)\n", result.File, result.Kind)
	} else {
		fmt.Fprintf(w, "INVALID: %s\n", result.File)
		for _, e := range result.Errors {
			fmt.Fprintf(w, "  - %s: %s\n", e.Path, e.Message)
		}
	}
	return nil
}
