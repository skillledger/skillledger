// Package scanner provides a pipeline for scanning discovered skills,
// computing content hashes, and checking against IOC databases and YARA rules.
package scanner

import (
	"crypto/sha256"
	"fmt"
	"io"
)

// HashFile computes the SHA-256 hex digest by reading from r.
func HashFile(r io.Reader) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", fmt.Errorf("hashing file: %w", err)
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// HashBytes computes the SHA-256 hex digest of a byte slice.
func HashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum[:])
}
