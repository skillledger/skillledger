package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// Lipgloss styles for explain output, matching the output/verify.go pattern.
var (
	explainAllowStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("2")) // green
	explainBlockStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("1")) // red
	explainWarnStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("3")) // yellow
	explainInfoStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("6"))            // cyan
)

// ExplainResult is the structured representation of a proxy decision,
// suitable for rendering as JSON or human-readable text.
type ExplainResult struct {
	ActionID    string `json:"action_id"`
	Timestamp   string `json:"timestamp"`
	Decision    string `json:"decision"`
	Direction   string `json:"direction"`
	Destination string `json:"destination,omitempty"`
	Method      string `json:"method,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
	SkillID     string `json:"skill_id,omitempty"`
	Reason      string `json:"reason"`
}

// ExplainResultFromEntry maps a DecisionEntry to an ExplainResult,
// formatting the Timestamp as RFC3339.
func ExplainResultFromEntry(entry DecisionEntry) *ExplainResult {
	ts := entry.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	return &ExplainResult{
		ActionID:    entry.ActionID,
		Timestamp:   ts.Format(time.RFC3339),
		Decision:    string(entry.Decision),
		Direction:   entry.Direction,
		Destination: entry.Destination,
		Method:      entry.Method,
		Protocol:    entry.Protocol,
		SkillID:     entry.SkillID,
		Reason:      entry.Reason,
	}
}

// FormatExplain writes an ExplainResult to w in JSON or human-readable text format.
// In text mode, the decision line is colored based on the action type.
func FormatExplain(w io.Writer, result *ExplainResult, jsonMode bool) error {
	if jsonMode {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}

	// Text mode with lipgloss styling.
	decisionStr := styleDecision(result.Decision)

	fmt.Fprintf(w, "Action:    %s\n", result.ActionID)
	fmt.Fprintf(w, "Time:      %s\n", result.Timestamp)
	fmt.Fprintf(w, "Decision:  %s\n", decisionStr)
	fmt.Fprintf(w, "Direction: %s\n", result.Direction)
	if result.Destination != "" {
		fmt.Fprintf(w, "Destination: %s\n", result.Destination)
	}
	if result.Method != "" {
		fmt.Fprintf(w, "Method:    %s\n", result.Method)
	}
	if result.Protocol != "" {
		fmt.Fprintf(w, "Protocol:  %s\n", result.Protocol)
	}
	if result.SkillID != "" {
		fmt.Fprintf(w, "Skill:     %s\n", result.SkillID)
	}
	fmt.Fprintf(w, "Reason:    %s\n", result.Reason)

	return nil
}

// styleDecision applies lipgloss color to the decision string based on action type.
func styleDecision(decision string) string {
	switch ActionType(decision) {
	case ActionAllow:
		return explainAllowStyle.Render("ALLOW")
	case ActionBlock:
		return explainBlockStyle.Render("BLOCK")
	case ActionWarn:
		return explainWarnStyle.Render("WARN")
	case ActionLog:
		return explainInfoStyle.Render("LOG")
	default:
		return decision
	}
}
