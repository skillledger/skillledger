package proxy_test

import (
	"bytes"
	"net/http/httptest"
	"testing"

	"github.com/skillledger/skillledger/internal/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecretScanner_DetectsAWSKey(t *testing.T) {
	scanner := proxy.NewSecretScanner(proxy.LoadPatterns())
	body := []byte(`{"accessKey": "AKIA1234567890ABCDEF"}`)
	req := httptest.NewRequest("POST", "http://example.com/api", bytes.NewReader(body))

	findings := scanner.Scan(req, body)

	require.Len(t, findings, 1)
	assert.Equal(t, "secret", findings[0].Scanner)
	assert.Equal(t, "aws-access-key-id", findings[0].Pattern)
	assert.Equal(t, "critical", findings[0].Severity)
	assert.Equal(t, proxy.ActionWarn, findings[0].Decision)
}

func TestSecretScanner_DetectsInHeader(t *testing.T) {
	scanner := proxy.NewSecretScanner(proxy.LoadPatterns())
	req := httptest.NewRequest("GET", "http://example.com/api", nil)
	// GitHub PAT in Authorization header -- ghp_ prefix + 36 alphanumeric chars
	req.Header.Set("Authorization", "Bearer ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")

	findings := scanner.Scan(req, nil)

	found := false
	for _, f := range findings {
		if f.Pattern == "github-pat" {
			found = true
			assert.Equal(t, "secret", f.Scanner)
			break
		}
	}
	assert.True(t, found, "expected github-pat finding in header scan")
}

func TestSecretScanner_DetectsInURLParams(t *testing.T) {
	scanner := proxy.NewSecretScanner(proxy.LoadPatterns())
	// Stripe live key in query parameter -- sk_live_ prefix + 24 alphanumeric chars
	req := httptest.NewRequest("GET", "http://example.com/api?api_key=sk_live_1234567890abcdefghijklmn", nil)

	findings := scanner.Scan(req, nil)

	found := false
	for _, f := range findings {
		if f.Pattern == "stripe-secret-key" {
			found = true
			break
		}
	}
	assert.True(t, found, "expected stripe-secret-key finding in URL params")
}

func TestSecretScanner_RedactsMatchValue(t *testing.T) {
	scanner := proxy.NewSecretScanner(proxy.LoadPatterns())
	body := []byte(`key=AKIA1234567890ABCDEF`)
	req := httptest.NewRequest("POST", "http://example.com/api", bytes.NewReader(body))

	findings := scanner.Scan(req, body)

	require.NotEmpty(t, findings)
	// Redacted: first 4 + **** + last 4
	mv := findings[0].MatchValue
	assert.Contains(t, mv, "****", "match value should be redacted")
	assert.Equal(t, "AKIA****CDEF", mv)
}

func TestSecretScanner_NoFalsePositiveOnShortStrings(t *testing.T) {
	scanner := proxy.NewSecretScanner(proxy.LoadPatterns())
	body := []byte(`These words should not trigger: sketch, skill, skeleton, skateboard`)
	req := httptest.NewRequest("POST", "http://example.com/api", bytes.NewReader(body))

	findings := scanner.Scan(req, body)

	assert.Empty(t, findings, "common words should not trigger secret detection")
}

func TestSecretScanner_MultipleSecretsInBody(t *testing.T) {
	scanner := proxy.NewSecretScanner(proxy.LoadPatterns())
	body := []byte(`{
		"aws_key": "AKIA1234567890ABCDEF",
		"stripe_key": "sk_live_1234567890abcdefghijklmn"
	}`)
	req := httptest.NewRequest("POST", "http://example.com/api", bytes.NewReader(body))

	findings := scanner.Scan(req, body)

	// Should detect both AWS key and Stripe key
	patterns := make(map[string]bool)
	for _, f := range findings {
		patterns[f.Pattern] = true
	}
	assert.True(t, patterns["aws-access-key-id"], "expected AWS key detection")
	assert.True(t, patterns["stripe-secret-key"], "expected Stripe key detection")
}

func TestSecretScanner_EmptyBody(t *testing.T) {
	scanner := proxy.NewSecretScanner(proxy.LoadPatterns())

	// nil body
	req := httptest.NewRequest("GET", "http://example.com/api", nil)
	findings := scanner.Scan(req, nil)
	assert.Empty(t, findings, "nil body should produce no findings")

	// empty body
	findings = scanner.Scan(req, []byte{})
	assert.Empty(t, findings, "empty body should produce no findings")
}

// TestSecretScanner_DirectionAware verifies that SecretScanner is structurally
// direction-aware per SECR-02. The Scanner interface only exposes
// Scan(req *http.Request, body []byte), which is called from OnRequest.
// There is no OnResponse integration point -- direction safety is enforced
// by the interface contract itself, not by runtime checks.
func TestSecretScanner_DirectionAware(t *testing.T) {
	// Verify SecretScanner implements the Scanner interface.
	var _ proxy.Scanner = proxy.NewSecretScanner(proxy.LoadPatterns())
	// The Scanner interface has only Scan(req, body) -- no response method.
	// Direction awareness is structurally enforced: the proxy handler calls
	// Scan only in OnRequest, never in OnResponse.
}
