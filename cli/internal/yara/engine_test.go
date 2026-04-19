package yara_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/skillledger/skillledger/internal/yara"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewEngine_CompileRules(t *testing.T) {
	dir := t.TempDir()
	rule := `rule test_rule {
    strings:
        $a = "malicious_string"
    condition:
        $a
}
`
	err := os.WriteFile(filepath.Join(dir, "test.yar"), []byte(rule), 0644)
	require.NoError(t, err)

	engine, err := yara.NewEngine(dir)
	require.NoError(t, err)
	assert.NotNil(t, engine)
}

func TestNewEngine_EmptyDir(t *testing.T) {
	dir := t.TempDir()

	_, err := yara.NewEngine(dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no .yar or .yara files")
}

func TestNewEngine_InvalidRule(t *testing.T) {
	dir := t.TempDir()
	// Syntactically invalid YARA rule
	rule := `rule broken_rule {
    this is not valid yara
}
`
	err := os.WriteFile(filepath.Join(dir, "broken.yar"), []byte(rule), 0644)
	require.NoError(t, err)

	_, err = yara.NewEngine(dir)
	require.Error(t, err)
}

func TestEngine_Scan_Match(t *testing.T) {
	dir := t.TempDir()
	rule := `rule test_rule {
    strings:
        $a = "malicious_string"
    condition:
        $a
}
`
	err := os.WriteFile(filepath.Join(dir, "test.yar"), []byte(rule), 0644)
	require.NoError(t, err)

	engine, err := yara.NewEngine(dir)
	require.NoError(t, err)

	matches, err := engine.Scan([]byte("this has malicious_string inside"))
	require.NoError(t, err)
	require.Len(t, matches, 1)
	assert.Equal(t, "test_rule", matches[0].RuleName)
}

func TestEngine_Scan_NoMatch(t *testing.T) {
	dir := t.TempDir()
	rule := `rule test_rule {
    strings:
        $a = "malicious_string"
    condition:
        $a
}
`
	err := os.WriteFile(filepath.Join(dir, "test.yar"), []byte(rule), 0644)
	require.NoError(t, err)

	engine, err := yara.NewEngine(dir)
	require.NoError(t, err)

	matches, err := engine.Scan([]byte("clean content"))
	require.NoError(t, err)
	assert.Empty(t, matches)
}

func TestEngine_Scan_MultipleRules(t *testing.T) {
	dir := t.TempDir()

	ruleA := `rule rule_a {
    strings:
        $a = "pattern_a"
    condition:
        $a
}
`
	ruleB := `rule rule_b {
    strings:
        $b = "pattern_b"
    condition:
        $b
}
`
	err := os.WriteFile(filepath.Join(dir, "rule_a.yar"), []byte(ruleA), 0644)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(dir, "rule_b.yar"), []byte(ruleB), 0644)
	require.NoError(t, err)

	engine, err := yara.NewEngine(dir)
	require.NoError(t, err)

	matches, err := engine.Scan([]byte("contains pattern_a and pattern_b here"))
	require.NoError(t, err)
	require.Len(t, matches, 2)

	ruleNames := make(map[string]bool)
	for _, m := range matches {
		ruleNames[m.RuleName] = true
	}
	assert.True(t, ruleNames["rule_a"])
	assert.True(t, ruleNames["rule_b"])
}

func TestEngine_Scan_WithTags(t *testing.T) {
	dir := t.TempDir()
	rule := `rule tagged_rule {
    meta:
        tags = "malware, trojan"
    strings:
        $a = "evil_payload"
    condition:
        $a
}
`
	err := os.WriteFile(filepath.Join(dir, "tagged.yar"), []byte(rule), 0644)
	require.NoError(t, err)

	engine, err := yara.NewEngine(dir)
	require.NoError(t, err)

	matches, err := engine.Scan([]byte("this contains evil_payload data"))
	require.NoError(t, err)
	require.Len(t, matches, 1)
	assert.Equal(t, "tagged_rule", matches[0].RuleName)
	assert.Equal(t, []string{"malware", "trojan"}, matches[0].Tags)
}

func TestEngine_Scan_YaraExtension(t *testing.T) {
	dir := t.TempDir()
	rule := `rule yara_ext_rule {
    strings:
        $a = "test_content"
    condition:
        $a
}
`
	err := os.WriteFile(filepath.Join(dir, "test.yara"), []byte(rule), 0644)
	require.NoError(t, err)

	engine, err := yara.NewEngine(dir)
	require.NoError(t, err)

	matches, err := engine.Scan([]byte("has test_content here"))
	require.NoError(t, err)
	require.Len(t, matches, 1)
	assert.Equal(t, "yara_ext_rule", matches[0].RuleName)
}
