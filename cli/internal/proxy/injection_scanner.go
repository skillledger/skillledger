package proxy

import (
	"encoding/json"
	"net/http"

	ahocorasick "github.com/cloudflare/ahocorasick"
)

// MCPMessageScanner is implemented by scanners that can inspect MCP JSON-RPC messages.
// Unlike the HTTP Scanner interface, this operates on parsed JSON-RPC messages
// with a direction indicator ("request" or "response").
type MCPMessageScanner interface {
	ScanMessage(msg *JSONRPCMessage, direction string) []Finding
}

// MCPToolCallResult is the result field of a tools/call JSON-RPC response.
type MCPToolCallResult struct {
	Content []MCPContent `json:"content"`
	IsError bool         `json:"isError"`
}

// MCPContent represents a content block in an MCP tool call result.
type MCPContent struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
	Data string `json:"data,omitempty"` // base64 for image/audio
}

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
	deepScan    bool                                          // --deep-scan flag: always invoke ML if available
	classifier  interface{ Classify(string) (float64, error) } // nil if ML unavailable
	mlThreshold float64                                       // default 0.85
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

// extractTextFromToolResult pulls all scannable text fields from a tool call result.
// Fields shorter than 50 chars are skipped per CONTEXT.md.
func extractTextFromToolResult(result json.RawMessage) []string {
	var r MCPToolCallResult
	if err := json.Unmarshal(result, &r); err != nil {
		return nil
	}
	var texts []string
	for _, c := range r.Content {
		if c.Type == "text" && len(c.Text) > 50 {
			texts = append(texts, c.Text)
		}
	}
	return texts
}

// scanText is the core scanning logic. It checks the allowlist, runs heuristic
// detection, handles base64 re-scanning, and optionally invokes the ML classifier.
func (s *InjectionScanner) scanText(text string, serverID string, toolName string) []Finding {
	// Stub -- will be implemented in Task 2.
	return nil
}

// scanBytes runs the two-pass Aho-Corasick + regex detection on raw bytes.
func (s *InjectionScanner) scanBytes(data []byte) []Finding {
	// Stub -- will be implemented in Task 2.
	return nil
}

// contextSnippet extracts a substring around the match location for inclusion
// in finding descriptions. Newlines are replaced with spaces. Result is
// truncated to 200 chars.
func contextSnippet(data []byte, matchStart int, radius int) string {
	// Stub -- will be implemented in Task 2.
	return ""
}
