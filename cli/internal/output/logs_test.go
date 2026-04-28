package output

import (
	"strings"
	"testing"
	"time"

	"github.com/skillledger/skillledger/internal/proxy"
	"github.com/stretchr/testify/assert"
)

func TestFormatLogEntry_BlockDecision(t *testing.T) {
	entry := proxy.DecisionEntry{
		ActionID:    "abc-123",
		Timestamp:   time.Date(2026, 1, 15, 10, 30, 45, 0, time.UTC),
		SkillID:     "my-skill",
		Direction:   "request",
		Destination: "evil.example.com",
		Decision:    proxy.ActionBlock,
		Reason:      "IOC match",
	}

	// With color disabled, should contain plain text markers.
	plain := FormatLogEntry(entry, false)
	assert.Contains(t, plain, "[BLOCK]")
	assert.Contains(t, plain, "[REQUEST]")
	assert.Contains(t, plain, "evil.example.com")
	assert.Contains(t, plain, "(my-skill)")
	assert.Contains(t, plain, "IOC match")
	assert.Contains(t, plain, "10:30:45")
}

func TestFormatLogEntry_WithFindings(t *testing.T) {
	entry := proxy.DecisionEntry{
		ActionID:    "def-456",
		Timestamp:   time.Date(2026, 3, 1, 14, 0, 0, 0, time.UTC),
		Direction:   "request",
		Destination: "api.example.com",
		Decision:    proxy.ActionWarn,
		Reason:      "secret detected",
		Findings: []proxy.Finding{
			{
				Scanner:     "secret",
				Severity:    "high",
				Description: "API key pattern",
				Decision:    proxy.ActionWarn,
			},
			{
				Scanner:     "yara",
				Severity:    "medium",
				Description: "custom_rule_match",
				Decision:    proxy.ActionWarn,
			},
		},
	}

	result := FormatLogEntry(entry, false)
	// Should contain scanner names in findings lines.
	assert.Contains(t, result, "secret: API key pattern (high)")
	assert.Contains(t, result, "yara: custom_rule_match (medium)")
	// Multi-line output.
	lines := strings.Split(result, "\n")
	assert.GreaterOrEqual(t, len(lines), 3, "should have header + 2 findings lines")
}

func TestFormatLogEntry_NoFindings(t *testing.T) {
	entry := proxy.DecisionEntry{
		ActionID:    "ghi-789",
		Timestamp:   time.Date(2026, 2, 20, 8, 0, 0, 0, time.UTC),
		Direction:   "response",
		Destination: "safe.example.com",
		Decision:    proxy.ActionAllow,
		Reason:      "no findings",
	}

	result := FormatLogEntry(entry, false)
	// No findings means single line only.
	assert.NotContains(t, result, "  ")
	lines := strings.Split(result, "\n")
	assert.Equal(t, 1, len(lines), "should be a single line with no findings")
}
