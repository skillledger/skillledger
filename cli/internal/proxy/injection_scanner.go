package proxy

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	ahocorasick "github.com/cloudflare/ahocorasick"
)

// MCPMessageScanner is implemented by scanners that can inspect MCP JSON-RPC messages.
// Unlike the HTTP Scanner interface, this operates on parsed JSON-RPC messages
// with a direction indicator ("request" or "response").
type MCPMessageScanner interface {
	ScanMessage(msg *JSONRPCMessage, direction string) []Finding
}

// base64BlobRe detects potential base64-encoded blobs in text.
// Minimum 40 chars of base64 alphabet followed by optional padding.
var base64BlobRe = regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,3}`)

// InjectionScanner detects prompt injection attacks in MCP tool outputs and
// HTTP response bodies. It implements both the Scanner interface (for HTTP) and
// the MCPMessageScanner interface (for MCP JSON-RPC messages).
//
// Detection uses a two-pass approach mirroring SecretScanner:
// 1. Aho-Corasick prefix scan for fast candidate filtering
// 2. Regex confirmation for each candidate match
//
// Base64-encoded payloads are decoded and re-scanned (depth limit 1).
// All findings default to ActionWarn (warn-only per CONTEXT.md).
type InjectionScanner struct {
	matcher     *ahocorasick.Matcher
	patterns    []InjectionPattern
	prefixes    []string
	allowlist   *InjectionAllowlist
	deepScan    bool                                           // --deep-scan flag: always invoke ML if available
	classifier  interface{ Classify(string) (float64, error) } // nil if ML unavailable
	mlThreshold float64                                        // default 0.85
}

// NewInjectionScanner creates an InjectionScanner with the bundled patterns and
// optional allowlist. If allowlist is nil, no findings are suppressed.
func NewInjectionScanner(allowlist *InjectionAllowlist) *InjectionScanner {
	patterns := LoadInjectionPatterns()
	prefixes := make([]string, len(patterns))
	for i, p := range patterns {
		prefixes[i] = p.Prefix
	}
	return &InjectionScanner{
		matcher:     ahocorasick.NewStringMatcher(prefixes),
		patterns:    patterns,
		prefixes:    prefixes,
		allowlist:   allowlist,
		mlThreshold: 0.85,
	}
}

// SetClassifier injects an ML classifier for enhanced detection.
// This avoids direct import of the ml package (per Pitfall 5).
func (s *InjectionScanner) SetClassifier(c interface{ Classify(string) (float64, error) }) {
	s.classifier = c
}

// SetDeepScan enables or disables deep scan mode (always invoke ML).
func (s *InjectionScanner) SetDeepScan(enabled bool) {
	s.deepScan = enabled
}

// Scan implements the Scanner interface for HTTP traffic.
// It scans the response body for prompt injection patterns.
func (s *InjectionScanner) Scan(req *http.Request, body []byte) []Finding {
	// For HTTP mode, no server/tool context for allowlist filtering.
	return s.scanText(string(body), "", "")
}

// ScanMessage implements the MCPMessageScanner interface.
// It only scans "response" direction messages that have a Result field.
func (s *InjectionScanner) ScanMessage(msg *JSONRPCMessage, direction string) []Finding {
	// Only scan response direction (tool outputs, not user requests).
	if direction != "response" {
		return nil
	}

	// Only scan messages that have a Result field.
	if msg.Result == nil {
		return nil
	}

	// Try to parse as MCPToolCallResult first for structured extraction.
	texts := extractTextFromToolResult(msg.Result)
	if len(texts) == 0 {
		// Fallback: scan raw JSON text if structured parse fails.
		raw := string(msg.Result)
		if len(raw) > 50 {
			texts = []string{raw}
		}
	}

	var allFindings []Finding
	for _, text := range texts {
		findings := s.scanText(text, "", "")
		allFindings = append(allFindings, findings...)
	}

	return deduplicateFindings(allFindings)
}

// scanText is the core scanning logic. It checks the allowlist, runs heuristic
// detection, handles base64 re-scanning, and optionally invokes the ML classifier.
func (s *InjectionScanner) scanText(text string, serverID string, toolName string) []Finding {
	// Step 1: Check allowlist -- if server+tool are set and allowlisted, skip scanning.
	if serverID != "" && toolName != "" && s.allowlist != nil && s.allowlist.IsAllowed(serverID, toolName) {
		return nil
	}

	data := []byte(text)

	// Step 2: Run heuristic Aho-Corasick + regex detection.
	findings := s.scanBytes(data)

	// Step 3: Check for base64-encoded payloads and re-scan decoded content.
	// Depth limit: 1 (per RESEARCH.md Pitfall 8).
	b64Matches := base64BlobRe.FindAll(data, -1)
	for _, b64 := range b64Matches {
		decoded, err := base64.StdEncoding.DecodeString(string(b64))
		if err != nil {
			// Try URL-safe base64 as well.
			decoded, err = base64.URLEncoding.DecodeString(string(b64))
			if err != nil {
				continue
			}
		}
		if len(decoded) <= 50 {
			continue
		}
		// Re-scan decoded content (depth=1, no further recursion).
		decodedFindings := s.scanBytes(decoded)
		for i := range decodedFindings {
			decodedFindings[i].Description += " (base64-decoded)"
		}
		findings = append(findings, decodedFindings...)
	}

	// Step 4: ML classifier (optional enhancement layer).
	if s.classifier != nil && (s.deepScan || len(findings) == 0) {
		score, err := s.classifier.Classify(text)
		if err == nil && score > s.mlThreshold {
			findings = append(findings, Finding{
				Scanner:     "injection",
				Severity:    "high",
				Description: fmt.Sprintf("ML classifier detected prompt injection (confidence: %.2f)", score),
				Pattern:     "ml-classifier",
				Decision:    ActionWarn,
			})
		}
	}

	// Step 5: Deduplicate by pattern name.
	return deduplicateFindings(findings)
}

// scanBytes runs the two-pass Aho-Corasick + regex detection on raw bytes.
// Pass 1: Aho-Corasick identifies which pattern prefixes appear in data.
// Pass 2: For each matched prefix, the corresponding regex confirms the match.
func (s *InjectionScanner) scanBytes(data []byte) []Finding {
	if len(data) == 0 {
		return nil
	}

	// Pass 1: Aho-Corasick prefix scan.
	hits := s.matcher.Match(data)

	var findings []Finding
	seen := make(map[string]bool)

	for _, idx := range hits {
		if idx < 0 || idx >= len(s.patterns) {
			continue
		}
		pat := s.patterns[idx]
		if seen[pat.Name] {
			continue
		}

		// Pass 2: regex confirmation.
		matchLoc := pat.Regex.FindIndex(data)
		if matchLoc == nil {
			continue
		}

		seen[pat.Name] = true
		match := data[matchLoc[0]:matchLoc[1]]

		// Truncate match value to 100 chars.
		matchStr := string(match)
		if len(matchStr) > 100 {
			matchStr = matchStr[:100]
		}

		// Build context snippet around the match location.
		snippet := contextSnippet(data, matchLoc[0], 200)

		findings = append(findings, Finding{
			Scanner:     "injection",
			Severity:    pat.Severity,
			Description: fmt.Sprintf("Prompt injection detected: %s (confidence: %.2f) ...context: %s", pat.Name, pat.Confidence, snippet),
			Pattern:     pat.Name,
			MatchValue:  matchStr,
			Decision:    ActionWarn,
		})
	}

	return findings
}

// contextSnippet extracts a substring around the match location for inclusion
// in finding descriptions. Newlines are replaced with spaces. Result is
// truncated to 200 chars.
func contextSnippet(data []byte, matchStart int, radius int) string {
	if len(data) == 0 {
		return ""
	}

	start := matchStart - radius
	if start < 0 {
		start = 0
	}
	end := matchStart + radius
	if end > len(data) {
		end = len(data)
	}

	snippet := string(data[start:end])
	// Replace newlines with spaces for single-line display.
	snippet = strings.ReplaceAll(snippet, "\n", " ")
	snippet = strings.ReplaceAll(snippet, "\r", " ")

	// Truncate to 200 chars.
	if len(snippet) > 200 {
		snippet = snippet[:200]
	}

	return snippet
}
