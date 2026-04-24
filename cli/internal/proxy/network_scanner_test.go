package proxy_test

import (
	"net/http/httptest"
	"testing"

	"github.com/skillledger/skillledger/internal/ioc"
	"github.com/skillledger/skillledger/internal/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newIOCDB(domains ...string) *ioc.Database {
	db := ioc.NewDatabase()
	for _, d := range domains {
		db.AddDomainEntry(ioc.DomainEntry{
			Domain:      d,
			Description: "known malicious: " + d,
			Severity:    "critical",
			Source:      "test",
		})
	}
	return db
}

func TestNetworkScanner_IOCMatch(t *testing.T) {
	scanner := proxy.NewNetworkScanner(newIOCDB("evil.com"))
	req := httptest.NewRequest("GET", "http://evil.com/path", nil)

	findings := scanner.Scan(req, nil)

	require.Len(t, findings, 1)
	assert.Equal(t, "network", findings[0].Scanner)
	assert.Equal(t, proxy.ActionBlock, findings[0].Decision)
	assert.Contains(t, findings[0].Description, "evil.com")
}

func TestNetworkScanner_IOCSubdomainMatch(t *testing.T) {
	scanner := proxy.NewNetworkScanner(newIOCDB("evil.com"))
	req := httptest.NewRequest("GET", "http://api.evil.com/data", nil)

	findings := scanner.Scan(req, nil)

	require.Len(t, findings, 1)
	assert.Equal(t, proxy.ActionBlock, findings[0].Decision)
	assert.Contains(t, findings[0].Description, "api.evil.com")
}

func TestNetworkScanner_IOCNoPartialMatch(t *testing.T) {
	scanner := proxy.NewNetworkScanner(newIOCDB("evil.com"))
	// "notevil.com" must NOT match "evil.com" -- proper suffix matching.
	req := httptest.NewRequest("GET", "http://notevil.com/path", nil)

	findings := scanner.Scan(req, nil)

	assert.Empty(t, findings, "notevil.com should not match evil.com IOC entry")
}

func TestNetworkScanner_SuspiciousTLD(t *testing.T) {
	scanner := proxy.NewNetworkScanner(newIOCDB()) // empty IOC DB
	req := httptest.NewRequest("GET", "http://random-site.tk/page", nil)

	findings := scanner.Scan(req, nil)

	require.Len(t, findings, 1)
	assert.Equal(t, "network", findings[0].Scanner)
	assert.Equal(t, proxy.ActionLog, findings[0].Decision)
	assert.Equal(t, "info", findings[0].Severity)
	assert.Contains(t, findings[0].Description, "suspicious TLD")
}

func TestNetworkScanner_SafeDomain(t *testing.T) {
	scanner := proxy.NewNetworkScanner(newIOCDB())
	req := httptest.NewRequest("GET", "http://api.github.com/repos", nil)

	findings := scanner.Scan(req, nil)

	assert.Empty(t, findings, "api.github.com should produce no findings")
}

func TestNetworkScanner_IOCTakesPrecedenceOverTLD(t *testing.T) {
	// IOC domain with a suspicious TLD should only produce the IOC finding.
	scanner := proxy.NewNetworkScanner(newIOCDB("malware.tk"))
	req := httptest.NewRequest("GET", "http://malware.tk/payload", nil)

	findings := scanner.Scan(req, nil)

	require.Len(t, findings, 1, "should produce exactly one finding, not two")
	assert.Equal(t, proxy.ActionBlock, findings[0].Decision, "IOC should take precedence")
}

func TestNetworkScanner_HostWithPort(t *testing.T) {
	scanner := proxy.NewNetworkScanner(newIOCDB("evil.com"))
	req := httptest.NewRequest("GET", "http://evil.com:8443/api", nil)

	findings := scanner.Scan(req, nil)

	require.Len(t, findings, 1)
	assert.Equal(t, proxy.ActionBlock, findings[0].Decision)
}

func TestNetworkScanner_EmptyHost(t *testing.T) {
	scanner := proxy.NewNetworkScanner(newIOCDB("evil.com"))
	req := httptest.NewRequest("GET", "http://example.com/path", nil)
	req.URL.Host = "" // Clear host

	findings := scanner.Scan(req, nil)

	assert.Empty(t, findings, "empty host should produce no findings and no panic")
}
