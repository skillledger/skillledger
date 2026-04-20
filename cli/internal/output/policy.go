package output

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/charmbracelet/lipgloss"
)

// PolicyCheckResult represents the outcome of evaluating a manifest against a policy.
type PolicyCheckResult struct {
	File       string   `json:"file"`
	Policy     string   `json:"policy"`
	Decision   string   `json:"decision"`
	Violations []string `json:"violations,omitempty"`
	Warnings   []string `json:"warnings,omitempty"`
}

// Lipgloss styles for policy result output.
var (
	allowStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("2"))  // green
	denyStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("1"))  // red
	warnStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("3"))  // yellow
)

// PrintPolicyResult writes a policy check result to w in text or JSON format.
func PrintPolicyResult(w io.Writer, result *PolicyCheckResult, jsonMode bool) error {
	if jsonMode {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}

	switch result.Decision {
	case "allow":
		fmt.Fprintf(w, "%s: %s (policy: %s)\n",
			allowStyle.Render("ALLOW"), result.File, result.Policy)
	case "deny":
		fmt.Fprintf(w, "%s: %s (policy: %s)\n",
			denyStyle.Render("DENY"), result.File, result.Policy)
		for _, v := range result.Violations {
			fmt.Fprintf(w, "  - %s\n", v)
		}
	case "warn":
		fmt.Fprintf(w, "%s: %s (policy: %s)\n",
			warnStyle.Render("WARN"), result.File, result.Policy)
		for _, warning := range result.Warnings {
			fmt.Fprintf(w, "  - %s\n", warning)
		}
	default:
		fmt.Fprintf(w, "%s: %s (policy: %s)\n", result.Decision, result.File, result.Policy)
	}

	return nil
}

// PrintCompileResult writes compiled Rego source to w in text or JSON format.
func PrintCompileResult(w io.Writer, regoSource string, jsonMode bool) error {
	if jsonMode {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]string{"rego": regoSource})
	}
	_, err := fmt.Fprint(w, regoSource)
	return err
}

// PrintPresetList writes the list of available presets to w in text or JSON format.
func PrintPresetList(w io.Writer, presets []string, jsonMode bool) error {
	if jsonMode {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string][]string{"presets": presets})
	}
	fmt.Fprintln(w, "Available presets:")
	for _, p := range presets {
		fmt.Fprintf(w, "  - %s\n", p)
	}
	return nil
}
