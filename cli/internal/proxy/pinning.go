package proxy

import (
	"encoding/json"
	"sync"
)

// requestTracker correlates JSON-RPC request IDs to their methods.
// This is needed because JSON-RPC responses only contain an id field,
// not the method name. The tracker allows the proxy to determine if
// a response is from tools/list, tools/call, etc.
type requestTracker struct {
	mu      sync.Mutex
	pending map[string]string // id -> method
}

// newRequestTracker creates a new requestTracker with an initialized map.
func newRequestTracker() *requestTracker {
	return &requestTracker{
		pending: make(map[string]string),
	}
}

// TrackRequest stores a mapping from a JSON-RPC request ID to its method.
func (t *requestTracker) TrackRequest(id json.RawMessage, method string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pending[string(id)] = method
}

// ResolveResponse looks up the method for a JSON-RPC response ID,
// removes the entry if found, and returns the method and whether it was found.
func (t *requestTracker) ResolveResponse(id json.RawMessage) (string, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	key := string(id)
	method, ok := t.pending[key]
	if ok {
		delete(t.pending, key)
	}
	return method, ok
}
