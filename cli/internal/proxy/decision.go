package proxy

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// DecisionEntry records a single proxy decision about intercepted traffic.
type DecisionEntry struct {
	ActionID    string     `json:"action_id"`
	Timestamp   time.Time  `json:"timestamp"`
	SkillID     string     `json:"skill_id,omitempty"`
	Direction   string     `json:"direction"`
	Destination string     `json:"destination,omitempty"`
	Method      string     `json:"method,omitempty"`
	Decision    ActionType `json:"decision"`
	Reason      string     `json:"reason"`
	Protocol    string     `json:"protocol,omitempty"`
	TrustTier   string     `json:"trust_tier,omitempty"`
	Findings    []Finding  `json:"findings,omitempty"`
}

// DecisionLog is a thread-safe ring buffer that records proxy decisions.
// The ring buffer limits memory exposure per T-09-02 threat mitigation.
// If a file writer is configured, each entry is also appended as JSONL.
type DecisionLog struct {
	mu      sync.RWMutex
	entries []DecisionEntry
	size    int
	head    int
	count   int
	fileW   *os.File // optional JSONL file writer
}

// NewDecisionLog creates a new DecisionLog with the given capacity.
func NewDecisionLog(size int) *DecisionLog {
	if size <= 0 {
		size = 1000
	}
	return &DecisionLog{
		entries: make([]DecisionEntry, size),
		size:    size,
	}
}

// SetFileWriter configures an append-only JSONL file for decision persistence.
// Each Record call will also write the entry as a JSON line to this file.
// The caller is responsible for closing the file when done.
func (d *DecisionLog) SetFileWriter(f *os.File) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.fileW = f
}

// Record adds a decision entry to the log. If ActionID is empty, one is
// generated automatically. If Timestamp is zero, it is set to the current time.
func (d *DecisionLog) Record(entry DecisionEntry) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if entry.ActionID == "" {
		entry.ActionID = NewActionID()
	}
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}

	d.entries[d.head] = entry
	d.head = (d.head + 1) % d.size
	if d.count < d.size {
		d.count++
	}

	// Append to JSONL file if configured.
	if d.fileW != nil {
		if data, err := json.Marshal(entry); err == nil {
			data = append(data, '\n')
			_, _ = d.fileW.Write(data)
		}
	}
}

// Lookup finds a decision entry by its action ID, scanning from newest to oldest.
func (d *DecisionLog) Lookup(actionID string) (DecisionEntry, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	for i := 0; i < d.count; i++ {
		idx := (d.head - 1 - i + d.size) % d.size
		if d.entries[idx].ActionID == actionID {
			return d.entries[idx], true
		}
	}
	return DecisionEntry{}, false
}

// Recent returns up to n most recent entries in reverse chronological order.
func (d *DecisionLog) Recent(n int) []DecisionEntry {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if n > d.count {
		n = d.count
	}

	result := make([]DecisionEntry, n)
	for i := 0; i < n; i++ {
		idx := (d.head - 1 - i + d.size) % d.size
		result[i] = d.entries[idx]
	}
	return result
}

// Count returns the current number of entries in the log.
func (d *DecisionLog) Count() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.count
}
