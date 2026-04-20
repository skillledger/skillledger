package output

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/charmbracelet/lipgloss"
)

// VerifyCheckResult represents the outcome of a full verification pipeline run,
// mapped from verify.VerifyResult for output rendering.
type VerifyCheckResult struct {
	Artifact   string             `json:"artifact"`
	Passed     bool               `json:"passed"`
	Steps      []VerifyStepOutput `json:"steps"`
	Violations []string           `json:"violations,omitempty"`
	Warnings   []string           `json:"warnings,omitempty"`
}

// VerifyStepOutput represents the outcome of a single verification step.
type VerifyStepOutput struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
	Error  string `json:"error,omitempty"`
}

// Lipgloss styles for verify result output.
var (
	verifyPassStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("2")) // green
	verifyFailStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("1")) // red
	verifyWarnStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("3")) // yellow
	verifyInfoStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("6"))            // cyan
	stepPassIcon    = lipgloss.NewStyle().Foreground(lipgloss.Color("2")).Render("PASS")
	stepFailIcon    = lipgloss.NewStyle().Foreground(lipgloss.Color("1")).Render("FAIL")
)

// PrintVerifyResult writes a verification result to w in text or JSON format.
// In text mode, it renders a styled summary with step-by-step pass/fail details.
// In JSON mode, it outputs the result as indented JSON.
func PrintVerifyResult(w io.Writer, result *VerifyCheckResult, jsonMode bool) error {
	if jsonMode {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}

	// Header line: PASS or FAIL with artifact path
	if result.Passed {
		fmt.Fprintf(w, "%s  %s\n", verifyPassStyle.Render("PASS"), result.Artifact)
	} else {
		fmt.Fprintf(w, "%s  %s\n", verifyFailStyle.Render("FAIL"), result.Artifact)
	}

	// Step-by-step details
	for _, step := range result.Steps {
		if step.Passed {
			fmt.Fprintf(w, "  [%s] %s", stepPassIcon, verifyInfoStyle.Render(step.Name))
			if step.Detail != "" {
				fmt.Fprintf(w, " -- %s", step.Detail)
			}
			fmt.Fprintln(w)
		} else {
			fmt.Fprintf(w, "  [%s] %s", stepFailIcon, verifyInfoStyle.Render(step.Name))
			if step.Error != "" {
				fmt.Fprintf(w, " -- %s", step.Error)
			}
			fmt.Fprintln(w)
		}
	}

	// Violations section
	if len(result.Violations) > 0 {
		fmt.Fprintf(w, "\n%s\n", verifyFailStyle.Render("Violations:"))
		for _, v := range result.Violations {
			fmt.Fprintf(w, "  - %s\n", v)
		}
	}

	// Warnings section
	if len(result.Warnings) > 0 {
		fmt.Fprintf(w, "\n%s\n", verifyWarnStyle.Render("Warnings:"))
		for _, warning := range result.Warnings {
			fmt.Fprintf(w, "  - %s\n", warning)
		}
	}

	fmt.Fprintln(w)
	return nil
}
