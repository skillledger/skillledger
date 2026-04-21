package builder

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/afero"

	"github.com/skillledger/skillledger/internal/canon"
)

// LockfileSource identifies the source repository for a built skill artifact.
type LockfileSource struct {
	Repository string `json:"repository"`
	Ref        string `json:"ref,omitempty"`
	Directory  string `json:"directory,omitempty"`
}

// Lockfile is the verifiable record of a skill build. It captures the artifact
// hash, source metadata, and placeholder fields for signing/provenance (Phase 4)
// and transparency log entry (Phase 5).
type Lockfile struct {
	SkillLedger    int            `json:"skillledger"`
	ArtifactID     string         `json:"artifact_id"`
	Version        string         `json:"version"`
	SHA256         string         `json:"sha256"`
	ContentAddress string         `json:"content_address"`
	BuiltAt        string         `json:"built_at"`
	Provenance     string         `json:"provenance,omitempty"`
	LogEntryID     string         `json:"log_entry_id,omitempty"`
	Source         LockfileSource `json:"source"`
}

// WriteLockfile serializes a Lockfile to JCS-canonical JSON (RFC 8785) and
// writes it to the given path. The output includes a trailing newline for
// POSIX compliance.
func WriteLockfile(fs afero.Fs, path string, lf *Lockfile) error {
	jsonBytes, err := json.Marshal(lf)
	if err != nil {
		return fmt.Errorf("writing lockfile: %w", err)
	}

	canonical, err := canon.Canonicalize(jsonBytes)
	if err != nil {
		return fmt.Errorf("writing lockfile: %w", err)
	}

	canonical = append(canonical, '\n')

	if err := afero.WriteFile(fs, path, canonical, 0644); err != nil {
		return fmt.Errorf("writing lockfile: %w", err)
	}

	return nil
}

// ReadLockfile reads and parses a lockfile from the given path.
func ReadLockfile(fs afero.Fs, path string) (*Lockfile, error) {
	data, err := afero.ReadFile(fs, path)
	if err != nil {
		return nil, fmt.Errorf("reading lockfile: %w", err)
	}

	var lf Lockfile
	if err := json.Unmarshal(data, &lf); err != nil {
		return nil, fmt.Errorf("reading lockfile: %w", err)
	}

	return &lf, nil
}
