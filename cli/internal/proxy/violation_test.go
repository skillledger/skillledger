package proxy

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestViolationWriter_AppendsJSONL(t *testing.T) {
	fs := afero.NewMemMapFs()
	vw, err := NewViolationWriter(fs, "/tmp/violations.jsonl")
	require.NoError(t, err)
	defer vw.Close()

	entry := DecisionEntry{
		ActionID:  "act-test0001",
		Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Direction: "request",
		Decision:  ActionWarn,
		Reason:    "test finding",
		Findings: []Finding{
			{Scanner: "secret", Severity: "high", Description: "API key", Decision: ActionWarn},
		},
	}

	err = vw.WriteFindings(entry)
	require.NoError(t, err)

	// Read file content
	data, err := afero.ReadFile(fs, "/tmp/violations.jsonl")
	require.NoError(t, err)

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	assert.Len(t, lines, 1, "should have written exactly one JSONL line")

	// Verify it's valid JSON containing the entry
	var decoded DecisionEntry
	err = json.Unmarshal([]byte(lines[0]), &decoded)
	require.NoError(t, err)
	assert.Equal(t, "act-test0001", decoded.ActionID)
	require.Len(t, decoded.Findings, 1)
	assert.Equal(t, "secret", decoded.Findings[0].Scanner)
}

func TestViolationWriter_FilePermissions(t *testing.T) {
	fs := afero.NewMemMapFs()
	vw, err := NewViolationWriter(fs, "/tmp/violations.jsonl")
	require.NoError(t, err)
	defer vw.Close()

	// Write something so file exists
	entry := DecisionEntry{
		ActionID: "act-perm0001",
		Decision: ActionWarn,
		Findings: []Finding{{Scanner: "test", Severity: "low", Description: "test", Decision: ActionWarn}},
	}
	err = vw.WriteFindings(entry)
	require.NoError(t, err)

	info, err := fs.Stat("/tmp/violations.jsonl")
	require.NoError(t, err)
	assert.Equal(t, "-rw-------", info.Mode().String(), "file should have 0600 permissions")
}

func TestViolationWriter_EmptyFindings_WritesNothing(t *testing.T) {
	fs := afero.NewMemMapFs()
	vw, err := NewViolationWriter(fs, "/tmp/violations.jsonl")
	require.NoError(t, err)
	defer vw.Close()

	// Entry with no findings
	entry := DecisionEntry{
		ActionID: "act-empty001",
		Decision: ActionAllow,
		Reason:   "no findings",
	}

	err = vw.WriteFindings(entry)
	require.NoError(t, err)

	data, err := afero.ReadFile(fs, "/tmp/violations.jsonl")
	require.NoError(t, err)
	assert.Empty(t, string(data), "should not write anything when findings are empty")
}

func TestViolationWriter_MultipleWrites_Appends(t *testing.T) {
	fs := afero.NewMemMapFs()
	vw, err := NewViolationWriter(fs, "/tmp/violations.jsonl")
	require.NoError(t, err)
	defer vw.Close()

	for i := 0; i < 3; i++ {
		entry := DecisionEntry{
			ActionID: "act-multi",
			Decision: ActionWarn,
			Findings: []Finding{{Scanner: "test", Severity: "medium", Description: "test", Decision: ActionWarn}},
		}
		err = vw.WriteFindings(entry)
		require.NoError(t, err)
	}

	data, err := afero.ReadFile(fs, "/tmp/violations.jsonl")
	require.NoError(t, err)

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	assert.Len(t, lines, 3, "should have three JSONL lines after three writes")
}
