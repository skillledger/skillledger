package proxy

import (
	"fmt"
	"net/http"

	ahocorasick "github.com/cloudflare/ahocorasick"
)

// SecretScanner detects leaked secrets in outbound HTTP requests using a
// two-pass approach: Aho-Corasick prefix matching narrows candidates, then
// per-pattern regex confirms the match. Only outbound request data is scanned
// (body, headers, URL) -- response bodies are never inspected (SECR-02).
type SecretScanner struct {
	matcher  *ahocorasick.Matcher
	patterns []SecretPattern
	prefixes []string
}

// NewSecretScanner creates a SecretScanner from the given patterns.
// It builds an Aho-Corasick automaton from the pattern prefixes for fast
// first-pass filtering.
func NewSecretScanner(patterns []SecretPattern) *SecretScanner {
	prefixes := make([]string, len(patterns))
	for i, p := range patterns {
		prefixes[i] = p.Prefix
	}
	return &SecretScanner{
		matcher:  ahocorasick.NewStringMatcher(prefixes),
		patterns: patterns,
		prefixes: prefixes,
	}
}

// Scan inspects the outbound HTTP request for secret patterns.
// It checks the request body, selected headers (Authorization, Cookie, X-API-Key),
// URL query parameter values, and the URL path.
// This method is only called for outbound requests (direction-aware per SECR-02).
func (s *SecretScanner) Scan(req *http.Request, body []byte) []Finding {
	var findings []Finding

	// Scan body bytes.
	findings = append(findings, s.scanBytes(body)...)

	// Scan sensitive headers.
	for _, hdr := range []string{"Authorization", "Cookie", "X-API-Key"} {
		if v := req.Header.Get(hdr); v != "" {
			findings = append(findings, s.scanBytes([]byte(v))...)
		}
	}

	// Scan URL query parameter values.
	for _, values := range req.URL.Query() {
		for _, v := range values {
			findings = append(findings, s.scanBytes([]byte(v))...)
		}
	}

	// Scan URL path for embedded tokens.
	if req.URL.Path != "" {
		findings = append(findings, s.scanBytes([]byte(req.URL.Path))...)
	}

	// Deduplicate across all scan locations: keep first finding per pattern name.
	return deduplicateFindings(findings)
}

// scanBytes runs the two-pass detection on raw bytes:
// 1. Aho-Corasick identifies which pattern prefixes appear in data.
// 2. For each matched prefix, the corresponding regex confirms the match.
func (s *SecretScanner) scanBytes(data []byte) []Finding {
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
		match := pat.Regex.Find(data)
		if match == nil {
			continue
		}

		seen[pat.Name] = true
		findings = append(findings, Finding{
			Scanner:     "secret",
			Severity:    pat.Severity,
			Description: fmt.Sprintf("Detected %s credential (%s)", pat.Provider, pat.Name),
			Pattern:     pat.Name,
			MatchValue:  Redact(string(match)),
			Decision:    ActionWarn,
		})
	}

	return findings
}

// deduplicateFindings removes duplicate findings with the same pattern name,
// keeping the first occurrence.
func deduplicateFindings(findings []Finding) []Finding {
	if len(findings) == 0 {
		return nil
	}
	seen := make(map[string]bool)
	var result []Finding
	for _, f := range findings {
		key := f.Pattern
		if key == "" {
			key = f.Description
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, f)
	}
	return result
}
