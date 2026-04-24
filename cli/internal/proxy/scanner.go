package proxy

import (
	"fmt"
	"net/http"
	"strings"
)

// Finding represents a single detection result from a scanner.
type Finding struct {
	Scanner     string     `json:"scanner"`
	Severity    string     `json:"severity"`
	Description string     `json:"description"`
	Pattern     string     `json:"pattern,omitempty"`
	MatchValue  string     `json:"match_value,omitempty"`
	Decision    ActionType `json:"decision"`
}

// Scanner is implemented by any detection module that inspects intercepted traffic.
type Scanner interface {
	Scan(req *http.Request, body []byte) []Finding
}

// ScanPipeline runs multiple scanners and merges their findings.
type ScanPipeline struct {
	scanners []Scanner
}

// NewScanPipeline creates a pipeline from the given scanners.
func NewScanPipeline(scanners ...Scanner) *ScanPipeline {
	return &ScanPipeline{scanners: scanners}
}

// Run executes all scanners against the request and body, returning merged findings.
func (p *ScanPipeline) Run(req *http.Request, body []byte) []Finding {
	var findings []Finding
	for _, s := range p.scanners {
		findings = append(findings, s.Scan(req, body)...)
	}
	return findings
}

// HighestDecision returns the most severe decision from a set of findings.
// Priority: Block > Warn > Log > Allow.
func HighestDecision(findings []Finding) ActionType {
	priority := map[ActionType]int{
		ActionBlock: 3,
		ActionWarn:  2,
		ActionLog:   1,
		ActionAllow: 0,
	}
	highest := ActionAllow
	for _, f := range findings {
		if priority[f.Decision] > priority[highest] {
			highest = f.Decision
		}
	}
	return highest
}

// Redact masks a secret value, showing only the first 4 and last 4 characters.
// Values of 8 characters or fewer are fully masked.
func Redact(s string) string {
	if len(s) <= 8 {
		return "****"
	}
	return s[:4] + "****" + s[len(s)-4:]
}

// FormatFindings creates a human-readable reason string from findings
// suitable for DecisionEntry.Reason.
func FormatFindings(findings []Finding) string {
	if len(findings) == 0 {
		return "no findings"
	}
	var parts []string
	for _, f := range findings {
		part := fmt.Sprintf("[%s] %s: %s", f.Severity, f.Scanner, f.Description)
		parts = append(parts, part)
	}
	return strings.Join(parts, "; ")
}
