package report_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/skillledger/skillledger/internal/ecosystem"
	"github.com/skillledger/skillledger/internal/report"
	"github.com/skillledger/skillledger/internal/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateJSON_ValidOutput(t *testing.T) {
	results := []scanner.ScanResult{
		{
			Skill:  ecosystem.DiscoveredSkill{ID: "skill-1", Path: "/tmp/skill1"},
			SHA256: "abc123",
			Status: "clean",
		},
		{
			Skill:  ecosystem.DiscoveredSkill{ID: "skill-2", Path: "/tmp/skill2"},
			SHA256: "def456",
			IOCMatch: &scanner.IOCMatchInfo{
				SHA256:      "def456",
				Description: "known malware",
				Severity:    "critical",
			},
			Status: "compromised",
		},
	}

	var buf bytes.Buffer
	err := report.GenerateJSON(&buf, results)
	require.NoError(t, err)

	var decoded []scanner.ScanResult
	err = json.Unmarshal(buf.Bytes(), &decoded)
	require.NoError(t, err)
	assert.Len(t, decoded, 2)
	assert.Equal(t, "abc123", decoded[0].SHA256)
	assert.Equal(t, "def456", decoded[1].SHA256)
}

func TestGenerateJSON_EmptyResults(t *testing.T) {
	var buf bytes.Buffer
	err := report.GenerateJSON(&buf, []scanner.ScanResult{})
	require.NoError(t, err)

	var decoded []scanner.ScanResult
	err = json.Unmarshal(buf.Bytes(), &decoded)
	require.NoError(t, err)
	assert.Len(t, decoded, 0)
}

func TestGenerateSARIF_ValidStructure(t *testing.T) {
	results := []scanner.ScanResult{
		{
			Skill:  ecosystem.DiscoveredSkill{ID: "skill-1", Path: "/tmp/skill1"},
			SHA256: "abc123",
			IOCMatch: &scanner.IOCMatchInfo{
				SHA256:      "abc123",
				Description: "test-ioc",
				Severity:    "high",
			},
			Status: "compromised",
		},
	}

	var buf bytes.Buffer
	err := report.GenerateSARIF(&buf, results)
	require.NoError(t, err)

	var parsed map[string]any
	err = json.Unmarshal(buf.Bytes(), &parsed)
	require.NoError(t, err)

	assert.Equal(t, "2.1.0", parsed["version"])

	runs, ok := parsed["runs"].([]any)
	require.True(t, ok)
	assert.Len(t, runs, 1)

	run := runs[0].(map[string]any)
	tool := run["tool"].(map[string]any)
	driver := tool["driver"].(map[string]any)
	assert.Equal(t, "skillledger", driver["name"])
}

func TestGenerateSARIF_IOCResult(t *testing.T) {
	results := []scanner.ScanResult{
		{
			Skill:  ecosystem.DiscoveredSkill{ID: "skill-1", Path: "/tmp/skill1"},
			SHA256: "abc123",
			IOCMatch: &scanner.IOCMatchInfo{
				SHA256:      "abc123",
				Description: "test-ioc",
				Severity:    "high",
			},
			Status: "compromised",
		},
	}

	var buf bytes.Buffer
	err := report.GenerateSARIF(&buf, results)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "SL001")
	assert.Contains(t, output, "test-ioc")
	assert.Contains(t, output, "error")
}

func TestGenerateSARIF_YARAResult(t *testing.T) {
	results := []scanner.ScanResult{
		{
			Skill:  ecosystem.DiscoveredSkill{ID: "skill-1", Path: "/tmp/skill1"},
			SHA256: "abc123",
			YARAMatches: []scanner.YARAMatchInfo{
				{RuleName: "test-rule", Tags: []string{"malware"}},
			},
			Status: "suspicious",
		},
	}

	var buf bytes.Buffer
	err := report.GenerateSARIF(&buf, results)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "SL002")
	assert.Contains(t, output, "test-rule")
	assert.Contains(t, output, "warning")
}

func TestGenerateSARIF_CleanResults(t *testing.T) {
	results := []scanner.ScanResult{
		{
			Skill:  ecosystem.DiscoveredSkill{ID: "skill-1", Path: "/tmp/skill1"},
			SHA256: "abc123",
			Status: "clean",
		},
		{
			Skill:  ecosystem.DiscoveredSkill{ID: "skill-2", Path: "/tmp/skill2"},
			SHA256: "def456",
			Status: "clean",
		},
	}

	var buf bytes.Buffer
	err := report.GenerateSARIF(&buf, results)
	require.NoError(t, err)

	var parsed map[string]any
	err = json.Unmarshal(buf.Bytes(), &parsed)
	require.NoError(t, err)

	runs := parsed["runs"].([]any)
	run := runs[0].(map[string]any)
	resultsArr, ok := run["results"].([]any)
	if ok {
		assert.Empty(t, resultsArr)
	}
	// If results key is absent or nil, that's also valid for clean scans
}
