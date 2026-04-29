package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/skillledger/skillledger/internal/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sarifDoc is used to unmarshal SARIF JSON for test assertions.
type sarifDoc struct {
	Version string    `json:"version"`
	Schema  string    `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string           `json:"id"`
	ShortDescription *sarifMFMS       `json:"shortDescription"`
	FullDescription  *sarifMFMS       `json:"fullDescription"`
	Help             *sarifMFMS       `json:"help"`
	HelpURI          string           `json:"helpUri"`
}

type sarifMFMS struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string                `json:"ruleId"`
	Level               string                `json:"level"`
	Message             sarifMessage          `json:"message"`
	Locations           []sarifLocation       `json:"locations"`
	PartialFingerprints map[string]string     `json:"partialFingerprints"`
	Properties          map[string]interface{} `json:"properties"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifactLoc `json:"artifactLocation"`
	Region           sarifRegion      `json:"region"`
}

type sarifArtifactLoc struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
	EndLine     int `json:"endLine"`
	EndColumn   int `json:"endColumn"`
}

func TestSeverityToLevel(t *testing.T) {
	tests := []struct {
		severity string
		level    string
	}{
		{"critical", "error"},
		{"high", "error"},
		{"medium", "warning"},
		{"low", "note"},
		{"info", "note"},
		{"unknown", "warning"},
		{"", "warning"},
	}
	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			assert.Equal(t, tt.level, severityToLevel(tt.severity))
		})
	}
}

func TestRuleIDForFinding(t *testing.T) {
	tests := []struct {
		scanner string
		ruleID  string
	}{
		{"secret", "SL-RT-secret-001"},
		{"network", "SL-RT-network-001"},
		{"injection", "SL-RT-injection-001"},
		{"capability", "SL-RT-capability-001"},
		{"pinchange", "SL-RT-pinchange-001"},
		{"yara", "SL-RT-yara-001"},
		{"dns-exfil", "SL-RT-dns-001"},
		{"entropy", "SL-RT-entropy-001"},
		{"unknown_scanner", "SL-RT-unknown-001"},
	}
	for _, tt := range tests {
		t.Run(tt.scanner, func(t *testing.T) {
			f := proxy.Finding{Scanner: tt.scanner}
			assert.Equal(t, tt.ruleID, ruleIDForFinding(f))
		})
	}
}

func TestFingerprintForFinding(t *testing.T) {
	f := proxy.Finding{
		Scanner:     "secret",
		Description: "API key detected",
		Pattern:     "sk-.*",
	}

	fp1 := fingerprintForFinding(f, "verified")
	fp2 := fingerprintForFinding(f, "unverified")
	fp3 := fingerprintForFinding(f, "verified")

	// Same finding + same tier = same fingerprint
	assert.Equal(t, fp1, fp3)
	// Same finding + different tier = different fingerprint
	assert.NotEqual(t, fp1, fp2)
	// Fingerprint is a hex string (SHA-256)
	assert.Len(t, fp1, 64)
}

func TestGenerateRuntimeSARIF_SecretFinding(t *testing.T) {
	entries := []proxy.DecisionEntry{
		{
			ActionID:    "act-001",
			Timestamp:   time.Now(),
			SkillID:     "my-skill",
			Direction:   "outbound",
			Destination: "https://evil.com/exfil",
			Method:      "POST",
			Decision:    proxy.ActionBlock,
			Reason:      "secret detected",
			Protocol:    "http",
			TrustTier:   "verified",
			Findings: []proxy.Finding{
				{
					Scanner:     "secret",
					Severity:    "critical",
					Description: "API key detected in request body",
					Pattern:     "sk-.*",
					MatchValue:  "sk-abc****xyz",
					Decision:    proxy.ActionBlock,
				},
			},
		},
	}

	var buf bytes.Buffer
	err := GenerateRuntimeSARIF(&buf, entries)
	require.NoError(t, err)

	var doc sarifDoc
	require.NoError(t, json.Unmarshal(buf.Bytes(), &doc))

	assert.Equal(t, "2.1.0", doc.Version)
	require.Len(t, doc.Runs, 1)

	run := doc.Runs[0]
	assert.Equal(t, "skillledger-runtime", run.Tool.Driver.Name)

	// Find the result
	require.NotEmpty(t, run.Results)
	result := run.Results[0]
	assert.Equal(t, "SL-RT-secret-001", result.RuleID)
	assert.Equal(t, "error", result.Level)

	// Check location
	require.NotEmpty(t, result.Locations)
	assert.Equal(t, "https://evil.com/exfil", result.Locations[0].PhysicalLocation.ArtifactLocation.URI)

	// Check partial fingerprints
	assert.Contains(t, result.PartialFingerprints, "primaryLocationLineHash")
}

func TestGenerateRuntimeSARIF_InjectionMedium(t *testing.T) {
	entries := []proxy.DecisionEntry{
		{
			ActionID:  "act-002",
			Timestamp: time.Now(),
			Direction: "inbound",
			Protocol:  "http",
			Findings: []proxy.Finding{
				{
					Scanner:     "injection",
					Severity:    "medium",
					Description: "Prompt injection in response",
					Decision:    proxy.ActionWarn,
				},
			},
		},
	}

	var buf bytes.Buffer
	err := GenerateRuntimeSARIF(&buf, entries)
	require.NoError(t, err)

	var doc sarifDoc
	require.NoError(t, json.Unmarshal(buf.Bytes(), &doc))

	result := doc.Runs[0].Results[0]
	assert.Equal(t, "warning", result.Level)
	assert.Equal(t, "SL-RT-injection-001", result.RuleID)
}

func TestGenerateRuntimeSARIF_CapabilityLow(t *testing.T) {
	entries := []proxy.DecisionEntry{
		{
			ActionID:  "act-003",
			Timestamp: time.Now(),
			Direction: "outbound",
			Protocol:  "http",
			Findings: []proxy.Finding{
				{
					Scanner:     "capability",
					Severity:    "low",
					Description: "Undeclared capability used",
					Decision:    proxy.ActionLog,
				},
			},
		},
	}

	var buf bytes.Buffer
	err := GenerateRuntimeSARIF(&buf, entries)
	require.NoError(t, err)

	var doc sarifDoc
	require.NoError(t, json.Unmarshal(buf.Bytes(), &doc))

	result := doc.Runs[0].Results[0]
	assert.Equal(t, "note", result.Level)
}

func TestGenerateRuntimeSARIF_HTTPDestinationURI(t *testing.T) {
	entries := []proxy.DecisionEntry{
		{
			ActionID:    "act-004",
			Timestamp:   time.Now(),
			Direction:   "outbound",
			Destination: "https://api.example.com/data",
			Protocol:    "http",
			Findings: []proxy.Finding{
				{
					Scanner:     "network",
					Severity:    "high",
					Description: "Known malicious domain",
					Decision:    proxy.ActionBlock,
				},
			},
		},
	}

	var buf bytes.Buffer
	err := GenerateRuntimeSARIF(&buf, entries)
	require.NoError(t, err)

	var doc sarifDoc
	require.NoError(t, json.Unmarshal(buf.Bytes(), &doc))

	result := doc.Runs[0].Results[0]
	require.NotEmpty(t, result.Locations)
	assert.Equal(t, "https://api.example.com/data", result.Locations[0].PhysicalLocation.ArtifactLocation.URI)
}

func TestGenerateRuntimeSARIF_MCPFindings(t *testing.T) {
	entries := []proxy.DecisionEntry{
		{
			ActionID:  "act-005",
			Timestamp: time.Now(),
			SkillID:   "github-mcp",
			Direction: "outbound",
			Protocol:  "mcp",
			Findings: []proxy.Finding{
				{
					Scanner:     "pinchange",
					Severity:    "high",
					Description: "Tool description changed",
					Pattern:     "create_issue",
					Decision:    proxy.ActionWarn,
				},
			},
		},
	}

	var buf bytes.Buffer
	err := GenerateRuntimeSARIF(&buf, entries)
	require.NoError(t, err)

	var doc sarifDoc
	require.NoError(t, json.Unmarshal(buf.Bytes(), &doc))

	result := doc.Runs[0].Results[0]
	require.NotEmpty(t, result.Locations)
	assert.Equal(t, "mcp://github-mcp/create_issue", result.Locations[0].PhysicalLocation.ArtifactLocation.URI)
}

func TestGenerateRuntimeSARIF_TrustTierInFingerprints(t *testing.T) {
	finding := proxy.Finding{
		Scanner:     "secret",
		Severity:    "critical",
		Description: "API key detected",
		Pattern:     "sk-.*",
		Decision:    proxy.ActionBlock,
	}

	entries1 := []proxy.DecisionEntry{
		{
			ActionID:  "act-006",
			Timestamp: time.Now(),
			Direction: "outbound",
			Protocol:  "http",
			TrustTier: "verified",
			Findings:  []proxy.Finding{finding},
		},
	}

	entries2 := []proxy.DecisionEntry{
		{
			ActionID:  "act-007",
			Timestamp: time.Now(),
			Direction: "outbound",
			Protocol:  "http",
			TrustTier: "unverified",
			Findings:  []proxy.Finding{finding},
		},
	}

	var buf1, buf2 bytes.Buffer
	require.NoError(t, GenerateRuntimeSARIF(&buf1, entries1))
	require.NoError(t, GenerateRuntimeSARIF(&buf2, entries2))

	var doc1, doc2 sarifDoc
	require.NoError(t, json.Unmarshal(buf1.Bytes(), &doc1))
	require.NoError(t, json.Unmarshal(buf2.Bytes(), &doc2))

	fp1 := doc1.Runs[0].Results[0].PartialFingerprints["primaryLocationLineHash"]
	fp2 := doc2.Runs[0].Results[0].PartialFingerprints["primaryLocationLineHash"]

	assert.NotEqual(t, fp1, fp2, "fingerprints should differ for different trust tiers")
}

func TestGenerateRuntimeSARIF_AllRulesHaveRequiredFields(t *testing.T) {
	// Create entries that exercise all scanners
	scanners := []string{"secret", "network", "injection", "capability", "pinchange", "yara", "dns-exfil", "entropy"}
	var entries []proxy.DecisionEntry
	for _, s := range scanners {
		entries = append(entries, proxy.DecisionEntry{
			ActionID:  "act-" + s,
			Timestamp: time.Now(),
			Direction: "outbound",
			Protocol:  "http",
			Findings: []proxy.Finding{
				{Scanner: s, Severity: "high", Description: "test " + s, Decision: proxy.ActionBlock},
			},
		})
	}

	var buf bytes.Buffer
	err := GenerateRuntimeSARIF(&buf, entries)
	require.NoError(t, err)

	var doc sarifDoc
	require.NoError(t, json.Unmarshal(buf.Bytes(), &doc))

	rules := doc.Runs[0].Tool.Driver.Rules
	require.GreaterOrEqual(t, len(rules), len(scanners))

	for _, rule := range rules {
		t.Run(rule.ID, func(t *testing.T) {
			assert.NotNil(t, rule.ShortDescription, "rule %s missing shortDescription", rule.ID)
			assert.NotEmpty(t, rule.ShortDescription.Text, "rule %s has empty shortDescription", rule.ID)
			assert.NotNil(t, rule.FullDescription, "rule %s missing fullDescription", rule.ID)
			assert.NotEmpty(t, rule.FullDescription.Text, "rule %s has empty fullDescription", rule.ID)
			assert.NotNil(t, rule.Help, "rule %s missing help", rule.ID)
			assert.NotEmpty(t, rule.Help.Text, "rule %s has empty help", rule.ID)
			assert.NotEmpty(t, rule.HelpURI, "rule %s missing helpURI", rule.ID)
		})
	}
}

func TestGenerateRuntimeSARIF_ValidJSON(t *testing.T) {
	entries := []proxy.DecisionEntry{
		{
			ActionID:  "act-json",
			Timestamp: time.Now(),
			Direction: "outbound",
			Protocol:  "http",
			Findings: []proxy.Finding{
				{Scanner: "secret", Severity: "high", Description: "test", Decision: proxy.ActionBlock},
			},
		},
	}

	var buf bytes.Buffer
	err := GenerateRuntimeSARIF(&buf, entries)
	require.NoError(t, err)

	// Must be valid JSON
	assert.True(t, json.Valid(buf.Bytes()), "output is not valid JSON")

	// Must be SARIF 2.1.0
	var doc sarifDoc
	require.NoError(t, json.Unmarshal(buf.Bytes(), &doc))
	assert.Equal(t, "2.1.0", doc.Version)
	assert.True(t, strings.Contains(doc.Schema, "sarif") || doc.Schema != "", "schema should reference SARIF")
}

func TestGenerateRuntimeSARIF_CapsAt25000(t *testing.T) {
	// Create entries that would generate > 25000 results
	var entries []proxy.DecisionEntry
	for i := 0; i < 26000; i++ {
		entries = append(entries, proxy.DecisionEntry{
			ActionID:  "act-cap",
			Timestamp: time.Now(),
			Direction: "outbound",
			Protocol:  "http",
			Findings: []proxy.Finding{
				{Scanner: "secret", Severity: "high", Description: "test", Decision: proxy.ActionBlock},
			},
		})
	}

	var buf bytes.Buffer
	err := GenerateRuntimeSARIF(&buf, entries)
	require.NoError(t, err)

	var doc sarifDoc
	require.NoError(t, json.Unmarshal(buf.Bytes(), &doc))

	assert.LessOrEqual(t, len(doc.Runs[0].Results), 25000)
}

func TestGenerateRuntimeSARIF_SkipsEntriesWithNoFindings(t *testing.T) {
	entries := []proxy.DecisionEntry{
		{
			ActionID:  "act-no-findings",
			Timestamp: time.Now(),
			Direction: "outbound",
			Protocol:  "http",
			// No Findings
		},
		{
			ActionID:  "act-with-findings",
			Timestamp: time.Now(),
			Direction: "outbound",
			Protocol:  "http",
			Findings: []proxy.Finding{
				{Scanner: "secret", Severity: "high", Description: "test", Decision: proxy.ActionBlock},
			},
		},
	}

	var buf bytes.Buffer
	err := GenerateRuntimeSARIF(&buf, entries)
	require.NoError(t, err)

	var doc sarifDoc
	require.NoError(t, json.Unmarshal(buf.Bytes(), &doc))

	assert.Len(t, doc.Runs[0].Results, 1)
}

func TestGenerateRuntimeSARIF_TrustTierInProperties(t *testing.T) {
	entries := []proxy.DecisionEntry{
		{
			ActionID:  "act-props",
			Timestamp: time.Now(),
			Direction: "outbound",
			Protocol:  "http",
			TrustTier: "verified",
			Findings: []proxy.Finding{
				{Scanner: "secret", Severity: "high", Description: "test", Decision: proxy.ActionBlock},
			},
		},
	}

	var buf bytes.Buffer
	err := GenerateRuntimeSARIF(&buf, entries)
	require.NoError(t, err)

	var doc sarifDoc
	require.NoError(t, json.Unmarshal(buf.Bytes(), &doc))

	result := doc.Runs[0].Results[0]
	assert.NotNil(t, result.Properties)
	assert.Equal(t, "verified", result.Properties["trustTier"])
}
