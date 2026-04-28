package output

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/skillledger/skillledger/internal/proxy"
)

// Decision color styles for log entry formatting.
var (
	logBlockStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("1")) // red
	logWarnStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("3")) // yellow
	logAllowStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("2")) // green
	logPassiveStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("8")) // dim
	logFindStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("5")) // magenta for findings detail
)

// decisionStyle returns the lipgloss style for a given ActionType.
func decisionStyle(decision proxy.ActionType) lipgloss.Style {
	switch decision {
	case proxy.ActionBlock:
		return logBlockStyle
	case proxy.ActionWarn:
		return logWarnStyle
	case proxy.ActionAllow:
		return logAllowStyle
	case proxy.ActionLog:
		return logPassiveStyle
	default:
		return logPassiveStyle
	}
}

// FormatLogEntry formats a single DecisionEntry as a human-readable string.
// Format:
//
//	[TIMESTAMP] [DECISION] [DIRECTION] DESTINATION (SKILL_ID) - REASON
//	  findings: SCANNER: DESCRIPTION (SEVERITY)
func FormatLogEntry(entry proxy.DecisionEntry, useColor bool) string {
	ts := entry.Timestamp.Format("15:04:05")
	decision := strings.ToUpper(string(entry.Decision))
	direction := strings.ToUpper(entry.Direction)

	var header string
	if useColor {
		style := decisionStyle(entry.Decision)
		decTag := style.Render("[" + decision + "]")
		header = fmt.Sprintf("[%s] %s [%s] %s", ts, decTag, direction, entry.Destination)
	} else {
		header = fmt.Sprintf("[%s] [%s] [%s] %s", ts, decision, direction, entry.Destination)
	}

	if entry.SkillID != "" {
		header += " (" + entry.SkillID + ")"
	}
	header += " - " + entry.Reason

	if len(entry.Findings) == 0 {
		return header
	}

	var lines []string
	lines = append(lines, header)
	for _, f := range entry.Findings {
		detail := fmt.Sprintf("  %s: %s (%s)", f.Scanner, f.Description, f.Severity)
		if useColor {
			detail = logFindStyle.Render(detail)
		}
		lines = append(lines, detail)
	}
	return strings.Join(lines, "\n")
}
