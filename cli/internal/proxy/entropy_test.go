package proxy_test

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/skillledger/skillledger/internal/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Shannon Entropy tests ---

func TestShannonEntropy_EmptyString(t *testing.T) {
	assert.Equal(t, 0.0, proxy.ShannonEntropy(""))
}

func TestShannonEntropy_SingleChar(t *testing.T) {
	assert.Equal(t, 0.0, proxy.ShannonEntropy("aaaa"))
}

func TestShannonEntropy_MaxEntropy(t *testing.T) {
	ent := proxy.ShannonEntropy("abcdefghijklmnopqrstuvwxyz")
	assert.Greater(t, ent, 4.5, "entropy of full alphabet should be > 4.5")
	assert.Less(t, ent, 5.0, "entropy of full alphabet should be < 5.0")
}

func TestShannonEntropy_KnownValue(t *testing.T) {
	ent := proxy.ShannonEntropy("password")
	assert.InDelta(t, 2.75, ent, 0.1, "entropy of 'password' should be ~2.75")
}

// --- DNS Exfil Scanner tests ---

func makeReq(host string) *http.Request {
	return &http.Request{
		URL: &url.URL{Host: host},
	}
}

func TestDNSExfilScanner_HighEntropySubdomain(t *testing.T) {
	scanner := proxy.NewDNSExfilScanner()
	// "dGhpcyBpcyBhIHRlc3Q" is base64 for "this is a test"
	req := makeReq("dGhpcyBpcyBhIHRlc3Q.evil.com")
	findings := scanner.Scan(req, nil)
	require.Len(t, findings, 1)
	assert.Equal(t, "dns-exfil", findings[0].Scanner)
	assert.Equal(t, proxy.ActionWarn, findings[0].Decision)
	assert.Equal(t, "high", findings[0].Severity)
}

func TestDNSExfilScanner_HexEncodedSubdomain(t *testing.T) {
	scanner := proxy.NewDNSExfilScanner()
	req := makeReq("a1b2c3d4e5f60789abcdef01.evil.com")
	findings := scanner.Scan(req, nil)
	require.Len(t, findings, 1)
	assert.Equal(t, "dns-exfil", findings[0].Scanner)
}

func TestDNSExfilScanner_NormalSubdomain(t *testing.T) {
	scanner := proxy.NewDNSExfilScanner()
	req := makeReq("api.github.com")
	findings := scanner.Scan(req, nil)
	assert.Empty(t, findings)
}

func TestDNSExfilScanner_CDNSubdomain(t *testing.T) {
	scanner := proxy.NewDNSExfilScanner()
	req := makeReq("d3js.cloudfront.net")
	findings := scanner.Scan(req, nil)
	assert.Empty(t, findings)
}

func TestDNSExfilScanner_ShortSubdomain(t *testing.T) {
	scanner := proxy.NewDNSExfilScanner()
	req := makeReq("www.example.com")
	findings := scanner.Scan(req, nil)
	assert.Empty(t, findings)
}

func TestDNSExfilScanner_NoSubdomain(t *testing.T) {
	scanner := proxy.NewDNSExfilScanner()
	req := makeReq("example.com")
	findings := scanner.Scan(req, nil)
	assert.Empty(t, findings)
}

func TestDNSExfilScanner_HostWithPort(t *testing.T) {
	scanner := proxy.NewDNSExfilScanner()
	req := makeReq("dGhpcyBpcyBhIHRlc3Q.evil.com:443")
	findings := scanner.Scan(req, nil)
	require.Len(t, findings, 1)
	assert.Equal(t, "dns-exfil", findings[0].Scanner)
}

// --- Cumulative Entropy Tracker tests ---

func highEntropyBody(t *testing.T) []byte {
	t.Helper()
	buf := make([]byte, 64)
	_, err := rand.Read(buf)
	require.NoError(t, err)
	return []byte(base64.StdEncoding.EncodeToString(buf))
}

func lowEntropyBody() []byte {
	return []byte(strings.Repeat("hello world ", 10))
}

func TestEntropyTracker_NoAlertBelowThreshold(t *testing.T) {
	tracker := proxy.NewEntropyTracker()
	body := lowEntropyBody()
	for i := 0; i < 15; i++ {
		req := makeReq("safe.example.com")
		findings := tracker.Scan(req, body)
		assert.Empty(t, findings, "request %d should not trigger alert", i)
	}
}

func TestEntropyTracker_AlertOnSustainedHighEntropy(t *testing.T) {
	tracker := proxy.NewEntropyTracker()
	var alerted bool
	for i := 0; i < 15; i++ {
		body := highEntropyBody(t)
		req := makeReq("exfil.evil.com")
		findings := tracker.Scan(req, body)
		if len(findings) > 0 {
			alerted = true
			assert.Equal(t, "entropy", findings[0].Scanner)
			assert.Equal(t, proxy.ActionLog, findings[0].Decision)
			assert.Equal(t, "medium", findings[0].Severity)
		}
	}
	assert.True(t, alerted, "should have triggered slow-drip alert after sufficient high-entropy requests")
}

func TestEntropyTracker_SeparateSessions(t *testing.T) {
	tracker := proxy.NewEntropyTracker()
	// Send high-entropy to host A and low-entropy to host B.
	for i := 0; i < 15; i++ {
		bodyA := highEntropyBody(t)
		reqA := makeReq("hostA.evil.com")
		tracker.Scan(reqA, bodyA)

		bodyB := lowEntropyBody()
		reqB := makeReq("hostB.safe.com")
		findings := tracker.Scan(reqB, bodyB)
		assert.Empty(t, findings, "host B should never trigger alert")
	}
	assert.Equal(t, 2, tracker.SessionCount())
}

func TestEntropyTracker_SlidingWindow(t *testing.T) {
	tracker := proxy.NewEntropyTracker()
	// Fill window with high entropy, then switch to low entropy.
	// After enough low-entropy samples replace the window, alerts should stop.
	for i := 0; i < 12; i++ {
		body := highEntropyBody(t)
		req := makeReq("target.com")
		tracker.Scan(req, body)
	}
	// Now send 50 low-entropy requests to flush the window.
	var lastFindings []proxy.Finding
	for i := 0; i < 50; i++ {
		body := lowEntropyBody()
		req := makeReq("target.com")
		lastFindings = tracker.Scan(req, body)
	}
	assert.Empty(t, lastFindings, "after flushing window with low entropy, no alert expected")
}

func TestEntropyTracker_MaxSessionsEviction(t *testing.T) {
	tracker := proxy.NewEntropyTracker()
	// Create maxSessions (100) sessions.
	for i := 0; i < 100; i++ {
		host := fmt.Sprintf("host%d.example.com", i)
		req := makeReq(host)
		tracker.Scan(req, []byte("data"))
	}
	assert.Equal(t, 100, tracker.SessionCount())

	// Adding one more should evict oldest, keeping count at 100.
	req := makeReq("overflow.example.com")
	tracker.Scan(req, []byte("data"))
	assert.Equal(t, 100, tracker.SessionCount())
}

func TestEntropyTracker_EmptyBody(t *testing.T) {
	tracker := proxy.NewEntropyTracker()
	req := makeReq("any.host.com")
	assert.Empty(t, tracker.Scan(req, nil))
	assert.Empty(t, tracker.Scan(req, []byte{}))
	assert.Equal(t, 0, tracker.SessionCount(), "empty body should not create session")
}

func TestEntropyTracker_ConcurrentAccess(t *testing.T) {
	tracker := proxy.NewEntropyTracker()
	var wg sync.WaitGroup
	for g := 0; g < 10; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			host := fmt.Sprintf("concurrent%d.example.com", id)
			for i := 0; i < 10; i++ {
				body := highEntropyBody(t)
				req := makeReq(host)
				tracker.Scan(req, body)
			}
		}(g)
	}
	wg.Wait()
	assert.Equal(t, 10, tracker.SessionCount(), "should have 10 sessions from 10 goroutines")
}
