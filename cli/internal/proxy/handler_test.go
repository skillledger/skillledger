package proxy_test

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/elazarl/goproxy"
	"github.com/rs/zerolog"
	"github.com/skillledger/skillledger/internal/ioc"
	"github.com/skillledger/skillledger/internal/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandler_OnRequest_SecretDetection(t *testing.T) {
	dl := proxy.NewDecisionLog(100)
	patterns := proxy.LoadPatterns()
	pipeline := proxy.NewScanPipeline(proxy.NewSecretScanner(patterns))
	h := proxy.NewHandler(dl, pipeline, nil, nil, nil, zerolog.Nop())

	body := `{"data": "my key is AKIA1234567890ABCDEF"}`
	req, err := http.NewRequest(http.MethodPost, "http://api.example.com/upload", strings.NewReader(body))
	require.NoError(t, err)

	ctx := &goproxy.ProxyCtx{Req: req}
	_, resp := h.OnRequest(req, ctx)

	// Secret detection produces ActionWarn, not ActionBlock -- request passes through.
	assert.Nil(t, resp, "request should not be blocked for secret detection (warn only)")

	entries := dl.Recent(1)
	require.Len(t, entries, 1)
	assert.Equal(t, proxy.ActionWarn, entries[0].Decision)
	assert.Contains(t, strings.ToLower(entries[0].Reason), "secret")
	assert.Contains(t, strings.ToLower(entries[0].Reason), "aws")
}

func TestHandler_OnRequest_IOCBlock(t *testing.T) {
	dl := proxy.NewDecisionLog(100)
	db := ioc.NewDatabase()
	db.AddDomainEntry(ioc.DomainEntry{
		Domain:      "evil.com",
		Description: "known malicious domain",
		Severity:    "critical",
		Source:      "test",
	})
	pipeline := proxy.NewScanPipeline(proxy.NewNetworkScanner(db))
	h := proxy.NewHandler(dl, pipeline, nil, nil, nil, zerolog.Nop())

	req, err := http.NewRequest(http.MethodGet, "http://evil.com/data", nil)
	require.NoError(t, err)

	ctx := &goproxy.ProxyCtx{Req: req}
	_, resp := h.OnRequest(req, ctx)

	// IOC match produces ActionBlock -- request returns 403.
	require.NotNil(t, resp, "IOC-matched request should be blocked")
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)

	entries := dl.Recent(1)
	require.Len(t, entries, 1)
	assert.Equal(t, proxy.ActionBlock, entries[0].Decision)
}

func TestHandler_OnRequest_NoFindings(t *testing.T) {
	dl := proxy.NewDecisionLog(100)
	patterns := proxy.LoadPatterns()
	pipeline := proxy.NewScanPipeline(
		proxy.NewSecretScanner(patterns),
		proxy.NewDNSExfilScanner(),
		proxy.NewEntropyTracker(),
	)
	h := proxy.NewHandler(dl, pipeline, nil, nil, nil, zerolog.Nop())

	req, err := http.NewRequest(http.MethodGet, "http://api.github.com/repos", strings.NewReader("hello world"))
	require.NoError(t, err)

	ctx := &goproxy.ProxyCtx{Req: req}
	_, resp := h.OnRequest(req, ctx)

	// No findings -- passthrough.
	assert.Nil(t, resp, "clean request should pass through")

	entries := dl.Recent(1)
	require.Len(t, entries, 1)
	assert.Equal(t, proxy.ActionAllow, entries[0].Decision)
}

func TestHandler_OnRequest_BodyPreserved(t *testing.T) {
	dl := proxy.NewDecisionLog(100)
	patterns := proxy.LoadPatterns()
	pipeline := proxy.NewScanPipeline(proxy.NewSecretScanner(patterns))
	h := proxy.NewHandler(dl, pipeline, nil, nil, nil, zerolog.Nop())

	originalBody := "test body content with AKIA1234567890ABCDEF"
	req, err := http.NewRequest(http.MethodPost, "http://api.example.com/upload", strings.NewReader(originalBody))
	require.NoError(t, err)

	ctx := &goproxy.ProxyCtx{Req: req}
	returnedReq, _ := h.OnRequest(req, ctx)

	// Body must be preserved for forwarding after scanning.
	restoredBody, err := io.ReadAll(returnedReq.Body)
	require.NoError(t, err)
	assert.Equal(t, originalBody, string(restoredBody), "request body must be preserved after scanning")
}

func TestHandler_OnRequest_NilPipeline(t *testing.T) {
	dl := proxy.NewDecisionLog(100)
	h := proxy.NewHandler(dl, nil, nil, nil, nil, zerolog.Nop())

	body := `{"secret": "AKIA1234567890ABCDEF"}`
	req, err := http.NewRequest(http.MethodPost, "http://api.example.com/upload", strings.NewReader(body))
	require.NoError(t, err)

	ctx := &goproxy.ProxyCtx{Req: req}
	_, resp := h.OnRequest(req, ctx)

	// Nil pipeline = backward compat passthrough.
	assert.Nil(t, resp, "nil pipeline should pass through")

	entries := dl.Recent(1)
	require.Len(t, entries, 1)
	assert.Equal(t, proxy.ActionAllow, entries[0].Decision)
}

func TestHandler_OnResponse_NoScanning(t *testing.T) {
	dl := proxy.NewDecisionLog(100)
	patterns := proxy.LoadPatterns()
	pipeline := proxy.NewScanPipeline(proxy.NewSecretScanner(patterns))
	h := proxy.NewHandler(dl, pipeline, nil, nil, nil, zerolog.Nop())

	// First make a request so we have an action ID in context.
	req, _ := http.NewRequest(http.MethodGet, "http://api.example.com/data", nil)
	ctx := &goproxy.ProxyCtx{Req: req}
	h.OnRequest(req, ctx)

	// Now create a response with a secret in the body.
	respBody := `{"key": "AKIA1234567890ABCDEF"}`
	resp := &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader(respBody)),
		Header:     make(http.Header),
		Request:    req,
	}

	result := h.OnResponse(resp, ctx)
	assert.Equal(t, resp, result, "response should pass through unchanged")

	// Check decision log: should have request entry + response entry.
	// Response entry should be ActionAllow (passthrough), NOT warn/block.
	entries := dl.Recent(2)
	require.Len(t, entries, 2)

	// Most recent entry is the response.
	responseEntry := entries[0]
	assert.Equal(t, "response", responseEntry.Direction)
	assert.Equal(t, proxy.ActionAllow, responseEntry.Decision, "response must NOT be scanned (SECR-02)")
}

func TestHandler_OnRequest_NilBody(t *testing.T) {
	dl := proxy.NewDecisionLog(100)
	patterns := proxy.LoadPatterns()
	pipeline := proxy.NewScanPipeline(proxy.NewSecretScanner(patterns))
	h := proxy.NewHandler(dl, pipeline, nil, nil, nil, zerolog.Nop())

	req := &http.Request{
		Method: http.MethodGet,
		URL:    &url.URL{Scheme: "http", Host: "example.com", Path: "/"},
		Header: make(http.Header),
	}

	ctx := &goproxy.ProxyCtx{Req: req}
	_, resp := h.OnRequest(req, ctx)

	assert.Nil(t, resp, "nil body request should pass through")

	entries := dl.Recent(1)
	require.Len(t, entries, 1)
	assert.Equal(t, proxy.ActionAllow, entries[0].Decision)
}
