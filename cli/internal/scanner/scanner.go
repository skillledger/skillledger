package scanner

import (
	"fmt"
	"io"
	"strings"

	"github.com/skillledger/skillledger/internal/ecosystem"
)

// ScanResult contains the result of scanning a single discovered skill.
type ScanResult struct {
	Skill       ecosystem.DiscoveredSkill `json:"skill"`
	SHA256      string                    `json:"sha256"`
	IOCMatch    *IOCMatchInfo             `json:"ioc_match,omitempty"`
	YARAMatches []YARAMatchInfo           `json:"yara_matches,omitempty"`
	Status      string                    `json:"status"` // "clean", "compromised", "suspicious"
}

// IOCMatchInfo describes a match against the IOC database.
type IOCMatchInfo struct {
	SHA256      string `json:"sha256"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

// YARAMatchInfo describes a YARA rule match.
type YARAMatchInfo struct {
	RuleName string   `json:"rule_name"`
	Tags     []string `json:"tags,omitempty"`
}

// IOCChecker is an interface for IOC matching (implemented by ioc.Database).
type IOCChecker interface {
	Match(sha256 string) (*IOCMatchInfo, bool)
}

// YARAScanner is an interface for YARA rule scanning (implemented by yara.Engine).
type YARAScanner interface {
	Scan(content []byte) ([]YARAMatchInfo, error)
}

// FileOpener abstracts filesystem access for reading skill files.
type FileOpener interface {
	Open(path string) (io.ReadCloser, error)
}

// Scanner runs the audit pipeline on discovered skills.
type Scanner struct {
	iocChecker  IOCChecker
	yaraScanner YARAScanner
	fileOpener  FileOpener
	maxFileSize int64 // per-file size limit in bytes (default 50MB)
}

// Option configures the Scanner.
type Option func(*Scanner)

// WithIOC configures the Scanner to check discovered skills against an IOC database.
func WithIOC(checker IOCChecker) Option {
	return func(s *Scanner) {
		s.iocChecker = checker
	}
}

// WithYARA configures the Scanner to run YARA rules against discovered skills.
func WithYARA(scanner YARAScanner) Option {
	return func(s *Scanner) {
		s.yaraScanner = scanner
	}
}

// WithMaxFileSize sets the maximum file size (in bytes) the scanner will read.
// Files larger than this limit are skipped. Default is 50MB.
func WithMaxFileSize(bytes int64) Option {
	return func(s *Scanner) {
		s.maxFileSize = bytes
	}
}

// NewScanner creates a Scanner with the given FileOpener and options.
func NewScanner(opener FileOpener, opts ...Option) *Scanner {
	s := &Scanner{
		fileOpener:  opener,
		maxFileSize: 50 << 20, // 50MB default (T-02-01 mitigation)
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Scan runs the audit pipeline on the given discovered skills.
// For each skill:
//  1. Hash each file to compute a skill-level SHA-256
//  2. Check IOC database (if configured)
//  3. Run YARA rules (if configured)
//  4. Determine status: "compromised", "suspicious", or "clean"
func (s *Scanner) Scan(skills []ecosystem.DiscoveredSkill) ([]ScanResult, error) {
	results := make([]ScanResult, 0, len(skills))

	for _, skill := range skills {
		result, err := s.scanSkill(skill)
		if err != nil {
			return nil, fmt.Errorf("scanning skill %s: %w", skill.ID, err)
		}
		results = append(results, result)
	}

	return results, nil
}

// scanSkill processes a single skill through the pipeline.
func (s *Scanner) scanSkill(skill ecosystem.DiscoveredSkill) (ScanResult, error) {
	result := ScanResult{
		Skill:  skill,
		Status: "clean",
	}

	// Step 1: Hash all files to compute skill-level SHA-256
	var allHashes []string
	var allContent []byte

	for _, filePath := range skill.Files {
		fullPath := skill.Path + "/" + filePath

		rc, err := s.fileOpener.Open(fullPath)
		if err != nil {
			return result, fmt.Errorf("open %s: %w", fullPath, err)
		}

		// Read content with size limit (T-02-01: DoS mitigation)
		content, err := readLimited(rc, s.maxFileSize)
		rc.Close()
		if err != nil {
			return result, fmt.Errorf("read %s: %w", fullPath, err)
		}

		fileHash := HashBytes(content)
		allHashes = append(allHashes, fileHash)
		allContent = append(allContent, content...)
	}

	// Compute skill-level hash from concatenated file hashes
	if len(allHashes) > 0 {
		combined := strings.Join(allHashes, "")
		result.SHA256 = HashBytes([]byte(combined))
	}

	// Step 2: IOC check
	if s.iocChecker != nil && result.SHA256 != "" {
		if match, found := s.iocChecker.Match(result.SHA256); found {
			result.IOCMatch = match
			result.Status = "compromised"
		}
	}

	// Step 3: YARA scan
	if s.yaraScanner != nil && len(allContent) > 0 {
		matches, err := s.yaraScanner.Scan(allContent)
		if err != nil {
			return result, fmt.Errorf("yara scan: %w", err)
		}
		if len(matches) > 0 {
			result.YARAMatches = matches
			if result.Status != "compromised" {
				result.Status = "suspicious"
			}
		}
	}

	return result, nil
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
