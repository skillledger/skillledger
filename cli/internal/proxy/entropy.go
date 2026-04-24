package proxy

import (
	"fmt"
	"math"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// ShannonEntropy calculates the Shannon entropy (bits per character) of a string.
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}
	length := float64(utf8.RuneCountInString(s))
	var entropy float64
	for _, count := range freq {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// DNSExfilScanner detects encoded data in subdomain labels before DNS resolution (SECR-04).
type DNSExfilScanner struct {
	entropyThreshold      float64 // default 4.0 bits/char for generic high-entropy
	encodedEntThreshold   float64 // default 3.0 bits/char when encoding indicator detected
	minSubdomainLength    int     // default 10 chars
}

// NewDNSExfilScanner creates a DNSExfilScanner with default thresholds.
func NewDNSExfilScanner() *DNSExfilScanner {
	return &DNSExfilScanner{
		entropyThreshold:    4.0,
		encodedEntThreshold: 3.0,
		minSubdomainLength:  10,
	}
}

var (
	base64Re = regexp.MustCompile(`^[A-Za-z0-9+/=_-]+$`)
	hexRe    = regexp.MustCompile(`^[0-9a-fA-F]+$`)
)

// isLikelyBase64 checks if a string looks like base64-encoded data.
func isLikelyBase64(s string) bool {
	return len(s) >= 16 && base64Re.MatchString(s)
}

// isLikelyHex checks if a string looks like hex-encoded data (after removing hyphens).
func isLikelyHex(s string) bool {
	cleaned := strings.ReplaceAll(s, "-", "")
	return len(cleaned) >= 16 && hexRe.MatchString(cleaned)
}

// extractSubdomain returns everything before the last 2 dot-separated parts of a hostname.
func extractSubdomain(hostname string) string {
	parts := strings.Split(hostname, ".")
	if len(parts) <= 2 {
		return ""
	}
	return strings.Join(parts[:len(parts)-2], ".")
}

// Scan inspects the request hostname for high-entropy subdomains that may indicate
// DNS exfiltration. It implements the Scanner interface.
func (d *DNSExfilScanner) Scan(req *http.Request, body []byte) []Finding {
	hostname := req.URL.Host
	// Strip port if present.
	if host, _, err := net.SplitHostPort(hostname); err == nil {
		hostname = host
	}

	subdomain := extractSubdomain(hostname)
	if len(subdomain) < d.minSubdomainLength {
		return nil
	}

	entropy := ShannonEntropy(subdomain)
	hasBase64 := isLikelyBase64(subdomain)
	hasHex := isLikelyHex(subdomain)
	hasEncoding := hasBase64 || hasHex

	// Two-tier threshold: encoding-constrained charsets (hex=16, base64=64 chars)
	// naturally produce lower entropy than arbitrary text. Use a lower threshold
	// when an encoding indicator is detected.
	threshold := d.entropyThreshold
	if hasEncoding {
		threshold = d.encodedEntThreshold
	}

	if entropy <= threshold {
		return nil
	}

	// Require length >= 20 OR encoding indicator to reduce false positives.
	if len(subdomain) < 20 && !hasEncoding {
		return nil
	}

	return []Finding{{
		Scanner:     "dns-exfil",
		Severity:    "high",
		Description: fmt.Sprintf("High-entropy subdomain (%.2f bits/char) in %s — possible DNS exfiltration", entropy, hostname),
		Pattern:     "dns-subdomain-entropy",
		MatchValue:  Redact(subdomain),
		Decision:    ActionWarn,
	}}
}

// Cumulative entropy tracking constants.
const (
	defaultWindowSize  = 50  // number of request entropy samples to keep
	defaultMaxSessions = 100 // max concurrent sessions tracked
	slowDripThreshold  = 5.0 // average entropy threshold
	slowDripMinSamples = 10  // minimum samples before alerting
)

// sessionState tracks per-session entropy samples.
type sessionState struct {
	window     []float64
	totalBytes int64
	created    time.Time
	lastSeen   time.Time
}

// EntropyTracker tracks cumulative entropy across requests per destination
// for slow-drip exfiltration detection (SECR-05).
type EntropyTracker struct {
	mu          sync.Mutex
	sessions    map[string]*sessionState
	windowSize  int
	maxSessions int
}

// NewEntropyTracker creates an EntropyTracker with default settings.
func NewEntropyTracker() *EntropyTracker {
	return &EntropyTracker{
		sessions:    make(map[string]*sessionState),
		windowSize:  defaultWindowSize,
		maxSessions: defaultMaxSessions,
	}
}

// evictOldest removes the session with the oldest lastSeen timestamp.
func (t *EntropyTracker) evictOldest() {
	var oldestKey string
	var oldestTime time.Time
	first := true
	for k, s := range t.sessions {
		if first || s.lastSeen.Before(oldestTime) {
			oldestKey = k
			oldestTime = s.lastSeen
			first = false
		}
	}
	if oldestKey != "" {
		delete(t.sessions, oldestKey)
	}
}

// averageEntropy calculates the mean entropy of a window of samples.
func averageEntropy(window []float64) float64 {
	if len(window) == 0 {
		return 0
	}
	var sum float64
	for _, v := range window {
		sum += v
	}
	return sum / float64(len(window))
}

// Scan tracks body entropy per destination and alerts on sustained high entropy.
// It implements the Scanner interface.
func (t *EntropyTracker) Scan(req *http.Request, body []byte) []Finding {
	if len(body) == 0 {
		return nil
	}

	sessionKey := req.URL.Host

	t.mu.Lock()
	defer t.mu.Unlock()

	// Evict oldest session if at capacity and this is a new key.
	if _, exists := t.sessions[sessionKey]; !exists && len(t.sessions) >= t.maxSessions {
		t.evictOldest()
	}

	state, exists := t.sessions[sessionKey]
	if !exists {
		state = &sessionState{
			window:  make([]float64, 0, t.windowSize),
			created: time.Now(),
		}
		t.sessions[sessionKey] = state
	}

	entropy := ShannonEntropy(string(body))

	// Sliding window: append and trim.
	state.window = append(state.window, entropy)
	if len(state.window) > t.windowSize {
		state.window = state.window[len(state.window)-t.windowSize:]
	}

	state.totalBytes += int64(len(body))
	state.lastSeen = time.Now()

	if len(state.window) >= slowDripMinSamples {
		avg := averageEntropy(state.window)
		if avg > slowDripThreshold {
			return []Finding{{
				Scanner:     "entropy",
				Severity:    "medium",
				Description: fmt.Sprintf("Sustained high entropy (%.2f avg over %d requests) to %s — possible slow-drip exfiltration", avg, len(state.window), sessionKey),
				Decision:    ActionLog,
			}}
		}
	}

	return nil
}

// Reset clears all tracked sessions.
func (t *EntropyTracker) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sessions = make(map[string]*sessionState)
}

// SessionCount returns the number of currently tracked sessions.
func (t *EntropyTracker) SessionCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.sessions)
}
