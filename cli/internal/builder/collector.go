// Package builder provides deterministic packaging for skill artifacts.
// It collects source files in sorted order and produces byte-identical
// archives with normalized metadata.
package builder

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/afero"
)

// FileEntry represents a single file collected from a source tree.
type FileEntry struct {
	// RelPath is the slash-separated relative path within the source tree.
	RelPath string
	// Content holds the raw file bytes.
	Content []byte
}

// DefaultIgnorePatterns defines paths excluded from collection by default.
var DefaultIgnorePatterns = []string{
	".git",
	".git/**",
	"*.skillledger.tar.gz",
	"skill-lock.json",
	".skillledgerignore",
	"node_modules/**",
	"__pycache__/**",
	"*.pyc",
	".DS_Store",
}

// maxFileSizeDefault is the default per-file size limit (50 MB).
const maxFileSizeDefault int64 = 50 * 1024 * 1024

// Collector walks a source tree, applies ignore patterns, and returns
// a deterministically sorted slice of FileEntry values.
type Collector struct {
	fs             afero.Fs
	ignorePatterns []string
	maxFileSize    int64
}

// Option configures a Collector.
type Option func(*Collector)

// WithIgnorePatterns appends additional ignore patterns to the defaults.
func WithIgnorePatterns(patterns []string) Option {
	return func(c *Collector) {
		c.ignorePatterns = append(c.ignorePatterns, patterns...)
	}
}

// WithMaxFileSize overrides the per-file size limit in bytes.
func WithMaxFileSize(bytes int64) Option {
	return func(c *Collector) {
		c.maxFileSize = bytes
	}
}

// NewCollector creates a Collector with DefaultIgnorePatterns and a 50 MB
// file-size limit, then applies any supplied options.
func NewCollector(fs afero.Fs, opts ...Option) *Collector {
	c := &Collector{
		fs:             fs,
		ignorePatterns: append([]string(nil), DefaultIgnorePatterns...),
		maxFileSize:    maxFileSizeDefault,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Collect walks sourceDir and returns a lexicographically sorted slice of
// FileEntry values. It respects DefaultIgnorePatterns, any patterns supplied
// via WithIgnorePatterns, and a .skillledgerignore file in sourceDir (if present).
// Symlinks and non-regular files are skipped.
func (c *Collector) Collect(sourceDir string) ([]FileEntry, error) {
	// Use a local copy of ignore patterns so that .skillledgerignore entries
	// from one Collect call do not accumulate across subsequent calls.
	patterns := append([]string(nil), c.ignorePatterns...)

	// Parse .skillledgerignore if it exists.
	ignorePath := filepath.Join(sourceDir, ".skillledgerignore")
	if data, err := afero.ReadFile(c.fs, ignorePath); err == nil {
		sc := bufio.NewScanner(strings.NewReader(string(data)))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			patterns = append(patterns, line)
		}
	}

	var entries []FileEntry

	walkErr := afero.Walk(c.fs, sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("walk %s: %w", path, err)
		}

		// Skip directories themselves; we only collect files.
		if info.IsDir() {
			return nil
		}

		// Skip symlinks and non-regular files.
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil
		}

		rel, err := filepath.Rel(sourceDir, path)
		if err != nil {
			return fmt.Errorf("compute relative path: %w", err)
		}
		relSlash := filepath.ToSlash(rel)

		// T-03-02: reject path traversal.
		if strings.Contains(relSlash, "..") {
			return fmt.Errorf("path traversal detected: %s", relSlash)
		}

		if isIgnored(relSlash, patterns) {
			return nil
		}

		// Read with size limit (T-03-03).
		f, err := c.fs.Open(path)
		if err != nil {
			return fmt.Errorf("open %s: %w", relSlash, err)
		}
		defer f.Close()

		content, err := readLimited(f, c.maxFileSize)
		if err != nil {
			return fmt.Errorf("read %s: %w", relSlash, err)
		}

		entries = append(entries, FileEntry{
			RelPath: relSlash,
			Content: content,
		})

		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].RelPath < entries[j].RelPath
	})

	return entries, nil
}

// isIgnored checks whether relPath matches any of the supplied ignore patterns.
func isIgnored(relPath string, patterns []string) bool {
	for _, pattern := range patterns {
		// Handle "dir/**" glob patterns.
		if strings.HasSuffix(pattern, "/**") {
			prefix := strings.TrimSuffix(pattern, "/**")
			// Match the directory itself or anything under it.
			if relPath == prefix || strings.HasPrefix(relPath, prefix+"/") {
				return true
			}
			continue
		}

		// Exact directory match (e.g., ".git").
		parts := strings.Split(relPath, "/")
		for _, part := range parts {
			if matched, _ := filepath.Match(pattern, part); matched {
				return true
			}
		}

		// Full-path match.
		if matched, _ := filepath.Match(pattern, relPath); matched {
			return true
		}
	}
	return false
}

// readLimited reads up to maxBytes from r. Returns an error if the content
// exceeds the limit.
func readLimited(r io.Reader, maxBytes int64) ([]byte, error) {
	limited := io.LimitReader(r, maxBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("file exceeds size limit of %d bytes", maxBytes)
	}
	return data, nil
}
