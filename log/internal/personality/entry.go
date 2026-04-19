// Package personality implements the SkillLedger transparency log personality.
// It wraps Tessera's appender with an HTTP API for adding log entries and
// serving tile data.
package personality

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// sha256Regex matches exactly 64 lowercase hex characters.
var sha256Regex = regexp.MustCompile(`^[a-f0-9]{64}$`)

// LogEntry is the canonical format for transparency log entries.
// Contains artifact hash and metadata -- NOT the full artifact content.
// This satisfies TLOG-02: log stores only hashes for scalability.
type LogEntry struct {
	ArtifactID     string `json:"artifact_id"`
	SHA256         string `json:"sha256"`
	ContentAddress string `json:"content_address"`
	PublishedAt    string `json:"published_at"`
	Publisher      string `json:"publisher"`
}

// ValidateEntry checks that a LogEntry has valid, non-empty fields with correct formats.
// Returns an error describing the first validation failure found.
func ValidateEntry(entry *LogEntry) error {
	if entry.ArtifactID == "" {
		return fmt.Errorf("artifact_id is required")
	}
	if !sha256Regex.MatchString(entry.SHA256) {
		return fmt.Errorf("sha256 must be exactly 64 lowercase hex characters, got %q", entry.SHA256)
	}
	if !strings.HasPrefix(entry.ContentAddress, "sha256-") {
		return fmt.Errorf("content_address must start with \"sha256-\", got %q", entry.ContentAddress)
	}
	if entry.PublishedAt == "" {
		return fmt.Errorf("published_at is required")
	}
	return nil
}

// SerializeEntry marshals a LogEntry to JSON bytes.
// Go struct field order is deterministic (declaration order), so the output
// is consistent across marshaling calls.
func SerializeEntry(entry *LogEntry) ([]byte, error) {
	data, err := json.Marshal(entry)
	if err != nil {
		return nil, fmt.Errorf("serializing log entry: %w", err)
	}
	return data, nil
}
