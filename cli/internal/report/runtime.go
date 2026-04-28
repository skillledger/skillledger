package report

import (
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/owenrumney/go-sarif/v3/pkg/report"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
	"github.com/rs/zerolog/log"
	"github.com/skillledger/skillledger/internal/proxy"
)

// maxSARIFResults is the GitHub Code Scanning limit for SARIF results per run.
const maxSARIFResults = 25000

// RuntimeRule defines a SARIF reporting descriptor for a runtime scanner.
type RuntimeRule struct {
	ID               string
	ShortDescription string
	FullDescription  string
	HelpText         string
	HelpURI          string
	DefaultLevel     string // "error", "warning", "note"
}

// runtimeRules maps scanner names to their SARIF rule definitions.
// Rule IDs follow the SL-RT-{scanner}-{NNN} pattern per CONTEXT.md.
var runtimeRules = map[string]RuntimeRule{
	"secret": {
		ID:               "SL-RT-secret-001",
		ShortDescription: "Secret exfiltration detected",
		FullDescription:  "Outbound request contains API key or token pattern sent to undeclared destination",
		HelpText:         "Review the flagged request for secret material. Rotate any exposed credentials immediately.",
		HelpURI:          "https://skillledger.dev/docs/runtime/secret",
		DefaultLevel:     "error",
	},
	"network": {
		ID:               "SL-RT-network-001",
		ShortDescription: "Malicious destination detected",
		FullDescription:  "Outbound request to known-malicious domain from IOC database",
		HelpText:         "The destination matched a known-malicious indicator. Block this traffic and investigate the skill.",
		HelpURI:          "https://skillledger.dev/docs/runtime/network",
		DefaultLevel:     "error",
	},
	"injection": {
		ID:               "SL-RT-injection-001",
		ShortDescription: "Prompt injection pattern detected",
		FullDescription:  "Tool output contains prompt injection patterns",
		HelpText:         "Inspect the tool output for injection attempts. Consider restricting this skill's permissions.",
		HelpURI:          "https://skillledger.dev/docs/runtime/injection",
		DefaultLevel:     "warning",
	},
	"capability": {
		ID:               "SL-RT-capability-001",
		ShortDescription: "Capability policy violation",
		FullDescription:  "Skill action not declared in capability manifest",
		HelpText:         "The skill performed an action not declared in its manifest. Update the manifest or restrict the skill.",
		HelpURI:          "https://skillledger.dev/docs/runtime/capability",
		DefaultLevel:     "note",
	},
	"pinchange": {
		ID:               "SL-RT-pinchange-001",
		ShortDescription: "MCP tool description change",
		FullDescription:  "MCP server changed tool description between sessions",
		HelpText:         "Tool descriptions should be stable. A change may indicate tool-poisoning. Verify with the MCP server maintainer.",
		HelpURI:          "https://skillledger.dev/docs/runtime/pinchange",
		DefaultLevel:     "warning",
	},
	"yara": {
		ID:               "SL-RT-yara-001",
		ShortDescription: "YARA rule match in runtime traffic",
		FullDescription:  "Custom YARA rule matched in proxy traffic",
		HelpText:         "A custom YARA detection rule matched traffic content. Review the matched rule and traffic.",
		HelpURI:          "https://skillledger.dev/docs/runtime/yara",
		DefaultLevel:     "warning",
	},
	"dns_exfil": {
		ID:               "SL-RT-dns-001",
		ShortDescription: "DNS exfiltration attempt",
		FullDescription:  "Data encoded in DNS subdomain queries",
		HelpText:         "Suspicious DNS queries detected that may encode exfiltrated data in subdomains.",
		HelpURI:          "https://skillledger.dev/docs/runtime/dns_exfil",
		DefaultLevel:     "error",
	},
	"entropy": {
		ID:               "SL-RT-entropy-001",
		ShortDescription: "Cumulative entropy anomaly",
		FullDescription:  "Slow-drip exfiltration detected via entropy tracking",
		HelpText:         "Cumulative entropy of outbound traffic exceeds threshold, indicating potential slow exfiltration.",
		HelpURI:          "https://skillledger.dev/docs/runtime/entropy",
		DefaultLevel:     "warning",
	},
}

// unknownRule is used for scanners not in the registry.
var unknownRule = RuntimeRule{
	ID:               "SL-RT-unknown-001",
	ShortDescription: "Unknown scanner finding",
	FullDescription:  "A finding from an unrecognized scanner was reported",
	HelpText:         "This finding came from a scanner not in the built-in registry. Review manually.",
	HelpURI:          "https://skillledger.dev/docs/runtime/unknown",
	DefaultLevel:     "warning",
}

// severityToLevel maps Finding.Severity to SARIF level per CONTEXT.md.
func severityToLevel(severity string) string {
	switch severity {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	case "low", "info":
		return "note"
	default:
		return "warning"
	}
}

// ruleIDForFinding returns the SARIF rule ID for a given Finding's scanner.
func ruleIDForFinding(f proxy.Finding) string {
	if rule, ok := runtimeRules[f.Scanner]; ok {
		return rule.ID
	}
	return unknownRule.ID
}

// fingerprintForFinding produces a SHA-256 fingerprint incorporating the trust tier,
// so the same finding from different tiers creates separate SARIF results.
func fingerprintForFinding(f proxy.Finding, trustTier string) string {
	ruleID := ruleIDForFinding(f)
	data := ruleID + "|" + f.Pattern + "|" + f.Description + "|" + trustTier
	h := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", h)
}

// GenerateRuntimeSARIF writes a SARIF 2.1.0 report to w from proxy DecisionEntry slices.
// Compatible with GitHub Code Scanning upload requirements.
// Results are capped at maxSARIFResults (25000) per GitHub limit.
func GenerateRuntimeSARIF(w io.Writer, entries []proxy.DecisionEntry) error {
	r := report.NewV210Report()

	run := sarif.NewRunWithInformationURI("skillledger-runtime", "https://skillledger.dev")

	// Register all rules from the registry with GitHub-required fields.
	for _, rule := range runtimeRules {
		run.AddRule(rule.ID).
			WithShortDescription(sarif.NewMultiformatMessageString().WithText(rule.ShortDescription)).
			WithFullDescription(sarif.NewMultiformatMessageString().WithText(rule.FullDescription)).
			WithHelp(sarif.NewMultiformatMessageString().WithText(rule.HelpText)).
			WithHelpURI(rule.HelpURI)
	}

	// Also register the unknown rule.
	run.AddRule(unknownRule.ID).
		WithShortDescription(sarif.NewMultiformatMessageString().WithText(unknownRule.ShortDescription)).
		WithFullDescription(sarif.NewMultiformatMessageString().WithText(unknownRule.FullDescription)).
		WithHelp(sarif.NewMultiformatMessageString().WithText(unknownRule.HelpText)).
		WithHelpURI(unknownRule.HelpURI)

	resultCount := 0
	for _, entry := range entries {
		if len(entry.Findings) == 0 {
			continue
		}
		for _, f := range entry.Findings {
			if resultCount >= maxSARIFResults {
				log.Warn().
					Int("limit", maxSARIFResults).
					Int("total_findings", countTotalFindings(entries)).
					Msg("SARIF result count exceeds GitHub limit; output truncated")
				break
			}

			ruleID := ruleIDForFinding(f)
			level := severityToLevel(f.Severity)

			// Determine artifact URI based on protocol.
			uri := entry.Destination
			if entry.Protocol == "mcp" {
				uri = fmt.Sprintf("mcp://%s/%s", entry.SkillID, f.Pattern)
			}
			if uri == "" {
				uri = "unknown"
			}

			result := run.CreateResultForRule(ruleID).
				WithLevel(level).
				WithMessage(sarif.NewTextMessage(f.Description)).
				AddLocation(
					sarif.NewLocationWithPhysicalLocation(
						sarif.NewPhysicalLocation().
							WithArtifactLocation(
								sarif.NewSimpleArtifactLocation(uri),
							).WithRegion(
							sarif.NewRegion().
								WithStartLine(1).
								WithStartColumn(1).
								WithEndLine(1).
								WithEndColumn(1),
						),
					),
				).
				WithPartialFingerprints(map[string]string{
					"primaryLocationLineHash": fingerprintForFinding(f, entry.TrustTier),
				})

			// Add trust tier to property bag if present.
			if entry.TrustTier != "" {
				result.WithProperties(
					sarif.NewPropertyBag().Add("trustTier", entry.TrustTier),
				)
			}

			resultCount++
		}
		if resultCount >= maxSARIFResults {
			break
		}
	}

	r.AddRun(run)
	return r.PrettyWrite(w)
}

// countTotalFindings counts all findings across all entries.
func countTotalFindings(entries []proxy.DecisionEntry) int {
	total := 0
	for _, e := range entries {
		total += len(e.Findings)
	}
	return total
}
