package proxy_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/rs/zerolog"
	"github.com/skillledger/skillledger/internal/proxy"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProxyServer_NewDefaults(t *testing.T) {
	s := proxy.NewProxyServer()
	assert.Equal(t, 8118, s.Port())
	assert.Contains(t, s.BaseDir(), ".skillledger")
}

func TestProxyServer_WithOptions(t *testing.T) {
	fs := afero.NewMemMapFs()
	s := proxy.NewProxyServer(
		proxy.WithPort(9999),
		proxy.WithBaseDir("/custom/dir"),
		proxy.WithFs(fs),
		proxy.WithDecisionLogSize(500),
	)
	assert.Equal(t, 9999, s.Port())
	assert.Equal(t, "/custom/dir", s.BaseDir())
}

func TestProxyServer_StartStop(t *testing.T) {
	fs := afero.NewMemMapFs()
	s := proxy.NewProxyServer(
		proxy.WithPort(0),
		proxy.WithBaseDir("/tmp/test-proxy"),
		proxy.WithFs(fs),
		proxy.WithLogger(zerolog.Nop()),
	)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Start(ctx)
	}()

	// Wait for server to start.
	time.Sleep(200 * time.Millisecond)

	addr := s.Addr()
	require.NotEmpty(t, addr, "server should have an address after starting")

	// Verify it's listening.
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	require.NoError(t, err)
	conn.Close()

	// Stop via context cancellation.
	cancel()

	select {
	case err := <-errCh:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("server did not stop in time")
	}
}

func TestProxyServer_PIDFile(t *testing.T) {
	fs := afero.NewMemMapFs()
	s := proxy.NewProxyServer(
		proxy.WithPort(0),
		proxy.WithBaseDir("/tmp/test-proxy-pid"),
		proxy.WithFs(fs),
		proxy.WithLogger(zerolog.Nop()),
	)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Start(ctx)
	}()

	time.Sleep(200 * time.Millisecond)

	// PID file should exist.
	pidExists, _ := afero.Exists(fs, "/tmp/test-proxy-pid/proxy/proxy.pid")
	assert.True(t, pidExists, "PID file should exist while running")

	// Port file should exist.
	portExists, _ := afero.Exists(fs, "/tmp/test-proxy-pid/proxy/proxy.port")
	assert.True(t, portExists, "port file should exist while running")

	cancel()
	select {
	case <-errCh:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not stop")
	}

	// PID file should be cleaned up.
	pidExists, _ = afero.Exists(fs, "/tmp/test-proxy-pid/proxy/proxy.pid")
	assert.False(t, pidExists, "PID file should be removed after stop")
}

func TestHandler_OnRequest_LogsDecision(t *testing.T) {
	dl := proxy.NewDecisionLog(100)
	h := proxy.NewHandler(dl, nil, nil, zerolog.Nop())

	req := httptest.NewRequest(http.MethodGet, "https://example.com/api", nil)
	ctx := &goproxy.ProxyCtx{
		Req: req,
	}

	resultReq, resultResp := h.OnRequest(req, ctx)
	assert.NotNil(t, resultReq)
	assert.Nil(t, resultResp, "passthrough should not return a response")

	// Verify decision was logged.
	assert.Equal(t, 1, dl.Count())
	entries := dl.Recent(1)
	require.Len(t, entries, 1)
	assert.Equal(t, "request", entries[0].Direction)
	assert.Equal(t, proxy.ActionAllow, entries[0].Decision)
	assert.Equal(t, "no findings", entries[0].Reason)
	assert.Equal(t, "example.com", entries[0].Destination)
	assert.Equal(t, http.MethodGet, entries[0].Method)

	// Verify protocol header was stripped before forwarding.
	assert.Empty(t, resultReq.Header.Get("X-SkillLedger-Proxy"),
		"protocol header should be stripped before forwarding")

	// Verify action ID stored in UserData for response correlation.
	assert.NotNil(t, ctx.UserData)
	actionID, ok := ctx.UserData.(string)
	assert.True(t, ok)
	assert.NotEmpty(t, actionID)
}

func TestHandler_OnResponse_LogsDecision(t *testing.T) {
	dl := proxy.NewDecisionLog(100)
	h := proxy.NewHandler(dl, nil, nil, zerolog.Nop())

	req := httptest.NewRequest(http.MethodPost, "https://api.example.com/data", nil)
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	ctx := &goproxy.ProxyCtx{
		Req:      req,
		UserData: "act-12345678",
	}

	result := h.OnResponse(resp, ctx)
	assert.NotNil(t, result)

	assert.Equal(t, 1, dl.Count())
	entries := dl.Recent(1)
	require.Len(t, entries, 1)
	assert.Equal(t, "response", entries[0].Direction)
	assert.Equal(t, proxy.ActionAllow, entries[0].Decision)
	assert.Equal(t, "api.example.com", entries[0].Destination)
	assert.Equal(t, http.MethodPost, entries[0].Method)
}

func TestIsProxyRunning_StalePID(t *testing.T) {
	fs := afero.NewMemMapFs()
	baseDir := "/tmp/test-stale"

	// Write a PID file with a nonexistent PID.
	_ = fs.MkdirAll(baseDir+"/proxy", 0700)
	_ = afero.WriteFile(fs, baseDir+"/proxy/proxy.pid", []byte("999999"), 0644)

	// Start a new server -- it should not fail with "already running".
	s := proxy.NewProxyServer(
		proxy.WithPort(0),
		proxy.WithBaseDir(baseDir),
		proxy.WithFs(fs),
		proxy.WithLogger(zerolog.Nop()),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Start(ctx)
	}()

	time.Sleep(200 * time.Millisecond)

	// Server should have started successfully (stale PID detected).
	addr := s.Addr()
	assert.NotEmpty(t, addr, "server should start despite stale PID file")

	cancel()
	select {
	case <-errCh:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not stop")
	}
}

func TestProxyServer_MITMInterception(t *testing.T) {
	// Create a TLS test server as the destination.
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify protocol header was stripped (T-09-04).
		assert.Empty(t, r.Header.Get("X-SkillLedger-Proxy"),
			"protocol header must not reach destination")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	}))
	defer backend.Close()

	fs := afero.NewMemMapFs()
	s := proxy.NewProxyServer(
		proxy.WithPort(0),
		proxy.WithBaseDir("/tmp/test-mitm"),
		proxy.WithFs(fs),
		proxy.WithLogger(zerolog.Nop()),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Start(ctx)
	}()

	time.Sleep(300 * time.Millisecond)

	addr := s.Addr()
	require.NotEmpty(t, addr)

	// Create HTTP client configured to use the proxy.
	proxyURL, _ := url.Parse("http://" + addr)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // test only
			},
		},
		Timeout: 5 * time.Second,
	}

	// Make a request through the proxy to the backend.
	resp, err := client.Get(backend.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Decision log should have entries (request + response).
	dl := s.DecisionLog()
	assert.GreaterOrEqual(t, dl.Count(), 1, "decision log should have entries after MITM")

	// Verify port file contains the correct port.
	portData, err := afero.ReadFile(fs, "/tmp/test-mitm/proxy/proxy.port")
	require.NoError(t, err)
	_, tcpPort, _ := net.SplitHostPort(addr)
	assert.Equal(t, tcpPort, string(portData))

	_ = strconv.Atoi // silence unused import if needed

	cancel()
	select {
	case <-errCh:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not stop")
	}
}
