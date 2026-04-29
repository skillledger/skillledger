package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/skillledger/skillledger/internal/canon"
	"github.com/spf13/afero"
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

// PinChangeSeverity classifies the severity of a tool definition change.
type PinChangeSeverity string

const (
	// SeverityCritical indicates a tool was added or removed mid-session (active rug-pull).
	SeverityCritical PinChangeSeverity = "critical"
	// SeverityHigh indicates a parameter schema change (new params, type changes).
	SeverityHigh PinChangeSeverity = "high"
	// SeverityMedium indicates a description text change (could be benign update).
	SeverityMedium PinChangeSeverity = "medium"
)

// PinEntry stores the hashes and metadata for a pinned tool definition.
type PinEntry struct {
	DescriptionHash string    `json:"description_hash"`
	SchemaHash      string    `json:"schema_hash"`
	FullHash        string    `json:"full_hash"`
	Description     string    `json:"description"`
	PinnedAt        time.Time `json:"pinned_at"`
	LastVerified    time.Time `json:"last_verified"`
}

// PinFile is the on-disk format for the pin store.
type PinFile struct {
	Version int                  `json:"version"`
	Pins    map[string]*PinEntry `json:"pins"`
}

// PinChange describes a detected change in a tool's definition.
type PinChange struct {
	ServerID   string            `json:"server_id"`
	ToolName   string            `json:"tool_name"`
	Severity   PinChangeSeverity `json:"severity"`
	OldHash    string            `json:"old_hash"`
	NewHash    string            `json:"new_hash"`
	OldDesc    string            `json:"old_description,omitempty"`
	NewDesc    string            `json:"new_description,omitempty"`
	MidSession bool              `json:"mid_session"`
	DetectedAt time.Time         `json:"detected_at"`
}

// pinKey builds the composite key for a pin entry: "serverID::toolName".
func pinKey(serverID, toolName string) string {
	return serverID + "::" + toolName
}

// hashToolFull computes a deterministic hash of a tool's name, description, and inputSchema
// using JCS canonicalization and SHA-256.
func hashToolFull(tool MCPTool) (string, error) {
	// Build a map of the fields to hash.
	// We must marshal the InputSchema as a raw JSON value in the map.
	var schemaVal interface{}
	if len(tool.InputSchema) > 0 {
		if err := json.Unmarshal(tool.InputSchema, &schemaVal); err != nil {
			// If inputSchema is not valid JSON, use it as a string
			schemaVal = string(tool.InputSchema)
		}
	}

	m := map[string]interface{}{
		"name":        tool.Name,
		"description": tool.Description,
		"inputSchema": schemaVal,
	}

	data, err := json.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("marshal tool for hashing: %w", err)
	}

	canonical, err := canon.Canonicalize(data)
	if err != nil {
		return "", fmt.Errorf("canonicalize tool for hashing: %w", err)
	}

	h := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(h[:]), nil
}

// hashField computes a SHA-256 hash of a single field value.
// It attempts JCS canonicalization first; if that fails (e.g., non-JSON string),
// it hashes the raw bytes.
func hashField(data []byte) string {
	canonical, err := canon.Canonicalize(data)
	if err != nil {
		// Not valid JSON; hash raw bytes.
		h := sha256.Sum256(data)
		return "sha256:" + hex.EncodeToString(h[:])
	}
	h := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(h[:])
}

// ToolPinStore manages pinned tool definitions with persistence and comparison.
// It follows the SSH known_hosts mental model: auto-pin on first connection,
// detect changes on subsequent connections.
type ToolPinStore struct {
	mu              sync.RWMutex
	pins            *PinFile
	path            string
	fs              afero.Fs
	sessionBaseline map[string]map[string]string // serverID -> toolName -> fullHash
}

// NewToolPinStore creates a new ToolPinStore backed by the given file path.
// CR-05: accepts afero.Fs for testability and convention compliance.
func NewToolPinStore(fs afero.Fs, path string) *ToolPinStore {
	return &ToolPinStore{
		pins: &PinFile{
			Version: 1,
			Pins:    make(map[string]*PinEntry),
		},
		fs:              fs,
		path:            path,
		sessionBaseline: make(map[string]map[string]string),
	}
}

// Load reads the pin file from disk via afero.Fs (CR-05).
// If the file does not exist, the store starts empty (no error).
func (s *ToolPinStore) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := afero.ReadFile(s.fs, s.path)
	if err != nil {
		if os.IsNotExist(err) {
			// No pin file yet; start fresh.
			s.pins = &PinFile{Version: 1, Pins: make(map[string]*PinEntry)}
			return nil
		}
		return fmt.Errorf("read pin file: %w", err)
	}

	var pf PinFile
	if err := json.Unmarshal(data, &pf); err != nil {
		return fmt.Errorf("decode pin file: %w", err)
	}

	if pf.Pins == nil {
		pf.Pins = make(map[string]*PinEntry)
	}
	s.pins = &pf
	return nil
}

// Save writes the pin file to disk via afero.Fs (CR-05).
// Uses atomic write: serialize to bytes, then write via afero.WriteFile.
func (s *ToolPinStore) Save() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Ensure directory exists.
	dir := filepath.Dir(s.path)
	if err := s.fs.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create pin directory: %w", err)
	}

	// Serialize to JSON.
	data, err := json.MarshalIndent(s.pins, "", "  ")
	if err != nil {
		return fmt.Errorf("encode pin file: %w", err)
	}

	// Write with restrictive permissions (0600 per threat model T-12-01).
	if err := afero.WriteFile(s.fs, s.path, data, 0600); err != nil {
		return fmt.Errorf("write pin file: %w", err)
	}

	return nil
}

// Pin stores or updates a pin entry for a single tool on a server.
func (s *ToolPinStore) Pin(serverID string, tool MCPTool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	fullHash, err := hashToolFull(tool)
	if err != nil {
		return fmt.Errorf("hash tool %q: %w", tool.Name, err)
	}

	descBytes, _ := json.Marshal(tool.Description)
	descHash := hashField(descBytes)
	schemaHash := hashField([]byte(tool.InputSchema))

	now := time.Now()
	key := pinKey(serverID, tool.Name)
	s.pins.Pins[key] = &PinEntry{
		DescriptionHash: descHash,
		SchemaHash:      schemaHash,
		FullHash:        fullHash,
		Description:     tool.Description,
		PinnedAt:        now,
		LastVerified:    now,
	}

	return nil
}

// PinAll stores pin entries for all tools from a server.
func (s *ToolPinStore) PinAll(serverID string, tools []MCPTool) error {
	for _, tool := range tools {
		if err := s.Pin(serverID, tool); err != nil {
			return err
		}
	}
	return nil
}

// SetSessionBaseline records the current tool hashes as the session baseline
// for mid-session change detection.
func (s *ToolPinStore) SetSessionBaseline(serverID string, tools []MCPTool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	baseline := make(map[string]string, len(tools))
	for _, tool := range tools {
		fullHash, err := hashToolFull(tool)
		if err != nil {
			continue
		}
		baseline[tool.Name] = fullHash
	}
	s.sessionBaseline[serverID] = baseline
}

// Check compares the provided tools against stored pins (between-session)
// or the session baseline (mid-session). Returns a list of detected changes.
func (s *ToolPinStore) Check(serverID string, tools []MCPTool, midSession bool) ([]PinChange, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var changes []PinChange
	now := time.Now()

	if midSession {
		return s.checkMidSession(serverID, tools, now)
	}

	return s.checkBetweenSession(serverID, tools, now, changes)
}

// checkBetweenSession compares tools against persisted pins.
func (s *ToolPinStore) checkBetweenSession(serverID string, tools []MCPTool, now time.Time, changes []PinChange) ([]PinChange, error) {
	for _, tool := range tools {
		key := pinKey(serverID, tool.Name)
		entry, exists := s.pins.Pins[key]
		if !exists {
			// New tool, not previously pinned. Not a change (will be pinned).
			continue
		}

		fullHash, err := hashToolFull(tool)
		if err != nil {
			return nil, fmt.Errorf("hash tool %q: %w", tool.Name, err)
		}

		if entry.FullHash == fullHash {
			// No change -- update last_verified time will be done separately.
			continue
		}

		// Determine severity by checking which fields changed.
		descBytes, _ := json.Marshal(tool.Description)
		newDescHash := hashField(descBytes)
		newSchemaHash := hashField([]byte(tool.InputSchema))

		severity := classifyPinChangeFromHashes(entry, newDescHash, newSchemaHash, false)

		changes = append(changes, PinChange{
			ServerID:   serverID,
			ToolName:   tool.Name,
			Severity:   severity,
			OldHash:    entry.FullHash,
			NewHash:    fullHash,
			OldDesc:    entry.Description,
			NewDesc:    tool.Description,
			MidSession: false,
			DetectedAt: now,
		})
	}

	return changes, nil
}

// checkMidSession compares tools against the in-memory session baseline.
func (s *ToolPinStore) checkMidSession(serverID string, tools []MCPTool, now time.Time) ([]PinChange, error) {
	baseline, exists := s.sessionBaseline[serverID]
	if !exists {
		// No baseline set; cannot detect mid-session changes.
		return nil, nil
	}

	var changes []PinChange
	currentTools := make(map[string]bool, len(tools))

	for _, tool := range tools {
		currentTools[tool.Name] = true
		fullHash, err := hashToolFull(tool)
		if err != nil {
			return nil, fmt.Errorf("hash tool %q: %w", tool.Name, err)
		}

		oldHash, wasInBaseline := baseline[tool.Name]
		if !wasInBaseline {
			// Tool added mid-session = critical.
			changes = append(changes, PinChange{
				ServerID:   serverID,
				ToolName:   tool.Name,
				Severity:   SeverityCritical,
				OldHash:    "",
				NewHash:    fullHash,
				NewDesc:    tool.Description,
				MidSession: true,
				DetectedAt: now,
			})
			continue
		}

		if oldHash == fullHash {
			continue
		}

		// Tool definition changed mid-session.
		// Look up the stored pin entry for old description.
		key := pinKey(serverID, tool.Name)
		entry := s.pins.Pins[key]

		descBytes, _ := json.Marshal(tool.Description)
		newDescHash := hashField(descBytes)
		newSchemaHash := hashField([]byte(tool.InputSchema))

		var severity PinChangeSeverity
		if entry != nil {
			severity = classifyPinChangeFromHashes(entry, newDescHash, newSchemaHash, true)
		} else {
			// No stored pin entry, but was in session baseline -- default to high.
			severity = SeverityHigh
		}

		oldDesc := ""
		if entry != nil {
			oldDesc = entry.Description
		}

		changes = append(changes, PinChange{
			ServerID:   serverID,
			ToolName:   tool.Name,
			Severity:   severity,
			OldHash:    oldHash,
			NewHash:    fullHash,
			OldDesc:    oldDesc,
			NewDesc:    tool.Description,
			MidSession: true,
			DetectedAt: now,
		})
	}

	// Detect removed tools (in baseline but not in current).
	for toolName, oldHash := range baseline {
		if !currentTools[toolName] {
			key := pinKey(serverID, toolName)
			oldDesc := ""
			if entry, ok := s.pins.Pins[key]; ok {
				oldDesc = entry.Description
			}

			changes = append(changes, PinChange{
				ServerID:   serverID,
				ToolName:   toolName,
				Severity:   SeverityCritical,
				OldHash:    oldHash,
				NewHash:    "",
				OldDesc:    oldDesc,
				MidSession: true,
				DetectedAt: now,
			})
		}
	}

	return changes, nil
}

// classifyPinChangeFromHashes determines the severity of a pin change
// based on which fields differ.
func classifyPinChangeFromHashes(old *PinEntry, newDescHash, newSchemaHash string, midSession bool) PinChangeSeverity {
	// Schema changed = high severity.
	if old.SchemaHash != newSchemaHash {
		return SeverityHigh
	}
	// Description changed = medium severity.
	if old.DescriptionHash != newDescHash {
		return SeverityMedium
	}
	// Something else changed (shouldn't normally reach here, but be safe).
	return SeverityMedium
}

// classifyPinChange classifies the severity of a tool definition change.
// Per CONTEXT.md:
// - Critical: tool added/removed mid-session
// - High: parameter schema changed
// - Medium: description text changed
func classifyPinChange(old *PinEntry, newTool MCPTool, midSession bool) PinChangeSeverity {
	if old == nil {
		if midSession {
			return SeverityCritical
		}
		return SeverityMedium
	}

	descBytes, _ := json.Marshal(newTool.Description)
	newDescHash := hashField(descBytes)
	newSchemaHash := hashField([]byte(newTool.InputSchema))

	return classifyPinChangeFromHashes(old, newDescHash, newSchemaHash, midSession)
}

// PinKeys returns all pin keys currently stored. This is used to check
// whether any pins exist for a given server prefix.
func (s *ToolPinStore) PinKeys() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	keys := make([]string, 0, len(s.pins.Pins))
	for k := range s.pins.Pins {
		keys = append(keys, k)
	}
	return keys
}

// Accept updates the pin entry for a tool to reflect its new definition.
// This is called when a user explicitly accepts a pin change.
func (s *ToolPinStore) Accept(serverID, toolName string, tool MCPTool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	fullHash, err := hashToolFull(tool)
	if err != nil {
		return fmt.Errorf("hash tool %q: %w", tool.Name, err)
	}

	descBytes, _ := json.Marshal(tool.Description)
	descHash := hashField(descBytes)
	schemaHash := hashField([]byte(tool.InputSchema))

	now := time.Now()
	key := pinKey(serverID, toolName)

	// Preserve original pinned_at if entry already exists.
	pinnedAt := now
	if existing, ok := s.pins.Pins[key]; ok {
		pinnedAt = existing.PinnedAt
	}

	s.pins.Pins[key] = &PinEntry{
		DescriptionHash: descHash,
		SchemaHash:      schemaHash,
		FullHash:        fullHash,
		Description:     tool.Description,
		PinnedAt:        pinnedAt,
		LastVerified:    now,
	}

	return nil
}
