package proxy_test

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/skillledger/skillledger/internal/proxy"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testdataDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	require.True(t, ok)
	return filepath.Join(filepath.Dir(filename), "testdata")
}

func TestYARAScanner_ScanMatch(t *testing.T) {
	dir := testdataDir(t)
	scanner := proxy.NewYARAScanner(afero.NewOsFs(),dir)
	require.NotNil(t, scanner, "scanner should be non-nil when valid rules dir exists")

	req := httptest.NewRequest(http.MethodPost, "http://example.com/api", nil)
	findings := scanner.Scan(req, []byte("payload contains exfiltrate_data_now marker"))

	require.Len(t, findings, 1)
	assert.Equal(t, "yara", findings[0].Scanner)
	assert.Equal(t, "runtime_malicious", findings[0].Description)
	assert.Equal(t, "high", findings[0].Severity)
	assert.Equal(t, proxy.ActionWarn, findings[0].Decision)
}

func TestYARAScanner_ScanNoMatch(t *testing.T) {
	dir := testdataDir(t)
	scanner := proxy.NewYARAScanner(afero.NewOsFs(),dir)
	require.NotNil(t, scanner)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	findings := scanner.Scan(req, []byte("clean content with no patterns"))

	assert.Empty(t, findings)
}

func TestYARAScanner_SeverityFromMeta(t *testing.T) {
	dir := testdataDir(t)
	scanner := proxy.NewYARAScanner(afero.NewOsFs(),dir)
	require.NotNil(t, scanner)

	req := httptest.NewRequest(http.MethodPost, "http://example.com/", nil)
	findings := scanner.Scan(req, []byte("exfiltrate_data_now"))

	require.Len(t, findings, 1)
	assert.Equal(t, "high", findings[0].Severity, "severity should come from YARA rule meta")
}

func TestYARAScanner_SeverityDefaultsMedium(t *testing.T) {
	dir := testdataDir(t)
	scanner := proxy.NewYARAScanner(afero.NewOsFs(),dir)
	require.NotNil(t, scanner)

	req := httptest.NewRequest(http.MethodPost, "http://example.com/", nil)
	findings := scanner.Scan(req, []byte("suspicious_callback"))

	require.Len(t, findings, 1)
	assert.Equal(t, "medium", findings[0].Severity, "severity should default to medium when not in rule meta")
}

func TestYARAScanner_FindingDescription(t *testing.T) {
	dir := testdataDir(t)
	scanner := proxy.NewYARAScanner(afero.NewOsFs(),dir)
	require.NotNil(t, scanner)

	req := httptest.NewRequest(http.MethodPost, "http://example.com/", nil)
	findings := scanner.Scan(req, []byte("exfiltrate_data_now"))

	require.Len(t, findings, 1)
	assert.Equal(t, "runtime_malicious", findings[0].Description, "description should be set to rule name")
}

func TestNewYARAScanner_EmptyDir(t *testing.T) {
	scanner := proxy.NewYARAScanner(afero.NewOsFs(),"")
	assert.Nil(t, scanner, "empty dir should return nil scanner")
}

func TestNewYARAScanner_NonexistentDir(t *testing.T) {
	scanner := proxy.NewYARAScanner(afero.NewOsFs(),"/nonexistent/path/to/rules")
	assert.Nil(t, scanner, "nonexistent dir should return nil scanner")
}
