package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/skillledger/skillledger/internal/ecosystem"
	"github.com/skillledger/skillledger/internal/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateSARIF_IOCResult(t *testing.T) {
	results := []scanner.ScanResult{
		{
			Skill: ecosystem.DiscoveredSkill{
				ID:   "test-skill",
				Path: "/path/to/skill",
			},
			SHA256: "abc123",
			IOCMatch: &scanner.IOCMatchInfo{
				SHA256:      "abc123",
				Description: "Known malicious skill",
				Severity:    "critical",
			},
			Status: "compromised",
		},
	}

	var buf bytes.Buffer
	err := GenerateSARIF(&buf, results)
	require.NoError(t, err)

	var doc sarifDoc
	require.NoError(t, json.Unmarshal(buf.Bytes(), &doc))

	assert.Equal(t, "2.1.0", doc.Version)
	require.Len(t, doc.Runs, 1)

	run := doc.Runs[0]
	assert.Equal(t, "skillledger", run.Tool.Driver.Name)
	require.NotEmpty(t, run.Results)

	result := run.Results[0]
	assert.Equal(t, "SL001", result.RuleID)
	assert.Equal(t, "error", result.Level)
	assert.Equal(t, "Known malicious skill", result.Message.Text)
}

func TestGenerateSARIF_YARAResult(t *testing.T) {
	results := []scanner.ScanResult{
		{
			Skill: ecosystem.DiscoveredSkill{
				ID:   "test-skill",
				Path: "/path/to/skill",
			},
			SHA256: "def456",
			YARAMatches: []scanner.YARAMatchInfo{
				{RuleName: "suspicious_shell_exec", Tags: []string{"shell"}},
			},
			Status: "suspicious",
		},
	}

	var buf bytes.Buffer
	err := GenerateSARIF(&buf, results)
	require.NoError(t, err)

	var doc sarifDoc
	require.NoError(t, json.Unmarshal(buf.Bytes(), &doc))

	result := doc.Runs[0].Results[0]
	assert.Equal(t, "SL002", result.RuleID)
	assert.Equal(t, "warning", result.Level)
	assert.Equal(t, "suspicious_shell_exec", result.Message.Text)
}

func TestGenerateSARIF_GitHubCompatFields(t *testing.T) {
	results := []scanner.ScanResult{
		{
			Skill: ecosystem.DiscoveredSkill{
				ID:   "compat-skill",
				Path: "/path/to/skill",
			},
			SHA256: "abc123",
			IOCMatch: &scanner.IOCMatchInfo{
				SHA256:      "abc123",
				Description: "IOC match",
				Severity:    "high",
			},
			YARAMatches: []scanner.YARAMatchInfo{
				{RuleName: "test_rule"},
			},
			Status: "compromised",
		},
	}

	var buf bytes.Buffer
	err := GenerateSARIF(&buf, results)
	require.NoError(t, err)

	var doc sarifDoc
	require.NoError(t, json.Unmarshal(buf.Bytes(), &doc))

	// Verify all rules have required GitHub Code Scanning fields.
	rules := doc.Runs[0].Tool.Driver.Rules
	require.GreaterOrEqual(t, len(rules), 2, "should have at least SL001 and SL002 rules")

	for _, rule := range rules {
		t.Run("rule_"+rule.ID, func(t *testing.T) {
			assert.NotNil(t, rule.ShortDescription, "rule %s missing shortDescription", rule.ID)
			if rule.ShortDescription != nil {
				assert.NotEmpty(t, rule.ShortDescription.Text, "rule %s has empty shortDescription.text", rule.ID)
			}

			assert.NotNil(t, rule.FullDescription, "rule %s missing fullDescription", rule.ID)
			if rule.FullDescription != nil {
				assert.NotEmpty(t, rule.FullDescription.Text, "rule %s has empty fullDescription.text", rule.ID)
			}

			assert.NotNil(t, rule.Help, "rule %s missing help", rule.ID)
			if rule.Help != nil {
				assert.NotEmpty(t, rule.Help.Text, "rule %s has empty help.text", rule.ID)
			}

			assert.NotEmpty(t, rule.HelpURI, "rule %s missing helpURI", rule.ID)
		})
	}

	// Verify all results have partialFingerprints.
	for i, result := range doc.Runs[0].Results {
		t.Run("result_fingerprint_"+result.RuleID, func(t *testing.T) {
			assert.NotNil(t, result.PartialFingerprints,
				"result %d (%s) missing partialFingerprints", i, result.RuleID)
			assert.Contains(t, result.PartialFingerprints, "primaryLocationLineHash",
				"result %d (%s) missing primaryLocationLineHash", i, result.RuleID)
			assert.NotEmpty(t, result.PartialFingerprints["primaryLocationLineHash"],
				"result %d (%s) has empty primaryLocationLineHash", i, result.RuleID)
		})
	}
}

func TestGenerateSARIF_EmptyResults(t *testing.T) {
	var buf bytes.Buffer
	err := GenerateSARIF(&buf, nil)
	require.NoError(t, err)

	assert.True(t, json.Valid(buf.Bytes()), "output should be valid JSON")

	var doc sarifDoc
	require.NoError(t, json.Unmarshal(buf.Bytes(), &doc))
	assert.Equal(t, "2.1.0", doc.Version)
	assert.Empty(t, doc.Runs[0].Results)
}
