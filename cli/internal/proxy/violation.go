package proxy

import (
	"encoding/json"
	"os"
	"sync"

	"github.com/spf13/afero"
)

// ViolationWriter appends violation entries as JSONL to an append-only file.
// It uses afero.Fs for testability per CLAUDE.md conventions.
// The file is created with 0600 permissions (T-14-03: owner-only read/write).
type ViolationWriter struct {
	file afero.File
	mu   sync.Mutex
}

// NewViolationWriter opens (or creates) the violations file at path using the
// given filesystem. The file is opened in append-only mode with 0600 permissions.
func NewViolationWriter(fs afero.Fs, path string) (*ViolationWriter, error) {
	f, err := fs.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	return &ViolationWriter{file: f}, nil
}

// WriteFindings appends the full DecisionEntry as a single JSON line if the
// entry contains findings. Entries with no findings are silently skipped.
func (vw *ViolationWriter) WriteFindings(entry DecisionEntry) error {
	if len(entry.Findings) == 0 {
		return nil
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	data = append(data, '\n')

	vw.mu.Lock()
	defer vw.mu.Unlock()
	_, err = vw.file.Write(data)
	return err
}

// Close closes the underlying file.
func (vw *ViolationWriter) Close() error {
	return vw.file.Close()
}
