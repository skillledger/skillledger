package proxy_test

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/skillledger/skillledger/internal/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExplainResultFromEntry(t *testing.T) {
	ts := time.Date(2026, 4, 21, 18, 30, 0, 0, time.UTC)
	entry := proxy.DecisionEntry{
		ActionID:    "act-a1b2c3d4",
		Timestamp:   ts,
		SkillID:     "my-mcp-server",
		Direction:   "request",
		Destination: "api.openai.com",
		Method:      "POST",
		Decision:    proxy.ActionAllow,
		Reason:      "passthrough (Phase 9)",
		Protocol:    "https",
	}

	result := proxy.ExplainResultFromEntry(entry)

	assert.Equal(t, "act-a1b2c3d4", result.ActionID)
	assert.Equal(t, "2026-04-21T18:30:00Z", result.Timestamp)
	assert.Equal(t, "allow", result.Decision)
	assert.Equal(t, "request", result.Direction)
	assert.Equal(t, "api.openai.com", result.Destination)
	assert.Equal(t, "POST", result.Method)
	assert.Equal(t, "https", result.Protocol)
	assert.Equal(t, "my-mcp-server", result.SkillID)
	assert.Equal(t, "passthrough (Phase 9)", result.Reason)
}

func TestFormatExplain_JSON(t *testing.T) {
	result := &proxy.ExplainResult{
		ActionID:  "act-deadbeef",
		Timestamp: "2026-04-21T18:30:00Z",
		Decision:  "allow",
		Direction: "request",
		Method:    "tools/list",
		Protocol:  "mcp-stdio",
		SkillID:   "test-server",
		Reason:    "passthrough (Phase 9)",
	}

	var buf bytes.Buffer
	err := proxy.FormatExplain(&buf, result, true)
	require.NoError(t, err)

	// Verify output is valid JSON.
	var parsed map[string]interface{}
	err = json.Unmarshal(buf.Bytes(), &parsed)
	require.NoError(t, err)

	assert.Equal(t, "act-deadbeef", parsed["action_id"])
	assert.Equal(t, "allow", parsed["decision"])
	assert.Equal(t, "passthrough (Phase 9)", parsed["reason"])
}

func TestFormatExplain_Text(t *testing.T) {
	result := &proxy.ExplainResult{
		ActionID:    "act-12345678",
		Timestamp:   "2026-04-21T18:30:00Z",
		Decision:    "allow",
		Direction:   "request",
		Destination: "api.openai.com",
		Method:      "POST",
		Protocol:    "https",
		SkillID:     "my-mcp-server",
		Reason:      "passthrough (Phase 9)",
	}

	var buf bytes.Buffer
	err := proxy.FormatExplain(&buf, result, false)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Action:")
	assert.Contains(t, output, "act-12345678")
	assert.Contains(t, output, "Decision:")
	assert.Contains(t, output, "Direction:")
	assert.Contains(t, output, "request")
	assert.Contains(t, output, "Reason:")
	assert.Contains(t, output, "passthrough (Phase 9)")
	assert.Contains(t, output, "Destination:")
	assert.Contains(t, output, "api.openai.com")
}

func TestFormatExplain_DecisionColors(t *testing.T) {
	// Test that each decision type renders its label.
	decisions := []struct {
		decision string
		label    string
	}{
		{"allow", "ALLOW"},
		{"block", "BLOCK"},
		{"warn", "WARN"},
		{"log", "LOG"},
	}

	for _, tc := range decisions {
		t.Run(tc.decision, func(t *testing.T) {
			result := &proxy.ExplainResult{
				ActionID:  "act-test",
				Timestamp: "2026-04-21T18:30:00Z",
				Decision:  tc.decision,
				Direction: "request",
				Reason:    "test",
			}

			var buf bytes.Buffer
			err := proxy.FormatExplain(&buf, result, false)
			require.NoError(t, err)

			// The decision label should appear in the output (may have ANSI escapes).
			assert.Contains(t, buf.String(), tc.label)
		})
	}
}
