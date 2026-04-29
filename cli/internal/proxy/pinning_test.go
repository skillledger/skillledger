package proxy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- MCPTool JSON round-trip tests ---

func TestMCPToolJSONRoundTrip(t *testing.T) {
	original := MCPTool{
		Name:        "read_file",
		Title:       "Read File",
		Description: "Reads a file from disk",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}`),
		Annotations: json.RawMessage(`{"readOnly":true}`),
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded MCPTool
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Name, decoded.Name)
	assert.Equal(t, original.Title, decoded.Title)
	assert.Equal(t, original.Description, decoded.Description)
	assert.JSONEq(t, string(original.InputSchema), string(decoded.InputSchema))
	assert.JSONEq(t, string(original.Annotations), string(decoded.Annotations))
}

func TestMCPToolJSONOmitsEmptyOptionalFields(t *testing.T) {
	tool := MCPTool{
		Name:        "list_files",
		Description: "Lists files in a directory",
		InputSchema: json.RawMessage(`{"type":"object"}`),
	}

	data, err := json.Marshal(tool)
	require.NoError(t, err)

	// Title and Annotations should be omitted (omitempty)
	var raw map[string]json.RawMessage
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	_, hasTitle := raw["title"]
	_, hasAnnotations := raw["annotations"]
	assert.False(t, hasTitle, "empty title should be omitted")
	assert.False(t, hasAnnotations, "empty annotations should be omitted")
}

// --- parseToolsList tests ---

func TestParseToolsListValid(t *testing.T) {
	result := json.RawMessage(`{
		"tools": [
			{
				"name": "read_file",
				"description": "Read a file",
				"inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}
			},
			{
				"name": "write_file",
				"description": "Write a file",
				"inputSchema": {"type": "object"}
			}
		]
	}`)

	tools, err := parseToolsList(result)
	require.NoError(t, err)
	require.Len(t, tools, 2)
	assert.Equal(t, "read_file", tools[0].Name)
	assert.Equal(t, "write_file", tools[1].Name)
}

func TestParseToolsListWithCursor(t *testing.T) {
	result := json.RawMessage(`{
		"tools": [{"name": "tool1", "description": "d", "inputSchema": {}}],
		"nextCursor": "abc123"
	}`)

	tools, err := parseToolsList(result)
	require.NoError(t, err)
	require.Len(t, tools, 1)
}

func TestParseToolsListInvalidJSON(t *testing.T) {
	result := json.RawMessage(`not json`)
	_, err := parseToolsList(result)
	assert.Error(t, err)
}

func TestParseToolsListEmptyTools(t *testing.T) {
	result := json.RawMessage(`{"tools": []}`)
	tools, err := parseToolsList(result)
	require.NoError(t, err)
	assert.Empty(t, tools)
}

// --- extractTextFromToolResult tests ---

func TestExtractTextFromToolResultFiltersShortText(t *testing.T) {
	result := json.RawMessage(`{
		"content": [
			{"type": "text", "text": "short"},
			{"type": "text", "text": "This is a long text that exceeds fifty characters in total length for testing"},
			{"type": "image", "data": "base64data"}
		],
		"isError": false
	}`)

	texts := extractTextFromToolResult(result)
	require.Len(t, texts, 1)
	assert.Contains(t, texts[0], "This is a long text")
}

func TestExtractTextFromToolResultExactly50Chars(t *testing.T) {
	// Exactly 50 chars should NOT be included (> 50, not >=)
	text50 := "12345678901234567890123456789012345678901234567890"
	assert.Len(t, text50, 50)

	result, _ := json.Marshal(MCPToolCallResult{
		Content: []MCPContent{
			{Type: "text", Text: text50},
		},
	})

	texts := extractTextFromToolResult(result)
	assert.Empty(t, texts)
}

func TestExtractTextFromToolResult51Chars(t *testing.T) {
	text51 := "123456789012345678901234567890123456789012345678901"
	assert.Len(t, text51, 51)

	result, _ := json.Marshal(MCPToolCallResult{
		Content: []MCPContent{
			{Type: "text", Text: text51},
		},
	})

	texts := extractTextFromToolResult(result)
	require.Len(t, texts, 1)
	assert.Equal(t, text51, texts[0])
}

func TestExtractTextFromToolResultInvalidJSON(t *testing.T) {
	result := json.RawMessage(`broken`)
	texts := extractTextFromToolResult(result)
	assert.Nil(t, texts)
}

func TestExtractTextFromToolResultIgnoresNonTextTypes(t *testing.T) {
	result := json.RawMessage(`{
		"content": [
			{"type": "image", "text": "This is a long text that exceeds fifty characters in total length for testing"},
			{"type": "resource", "text": "Another long text that exceeds fifty characters in total length for testing"}
		],
		"isError": false
	}`)

	texts := extractTextFromToolResult(result)
	assert.Empty(t, texts)
}

// --- requestTracker tests ---

func TestRequestTrackerTrackAndResolve(t *testing.T) {
	tracker := newRequestTracker()

	id := json.RawMessage(`1`)
	tracker.TrackRequest(id, "tools/list")

	method, ok := tracker.ResolveResponse(id)
	assert.True(t, ok)
	assert.Equal(t, "tools/list", method)

	// Second resolve should fail (entry deleted)
	method, ok = tracker.ResolveResponse(id)
	assert.False(t, ok)
	assert.Empty(t, method)
}

func TestRequestTrackerUnknownID(t *testing.T) {
	tracker := newRequestTracker()

	method, ok := tracker.ResolveResponse(json.RawMessage(`999`))
	assert.False(t, ok)
	assert.Empty(t, method)
}

func TestRequestTrackerStringIDs(t *testing.T) {
	tracker := newRequestTracker()

	id := json.RawMessage(`"req-abc-123"`)
	tracker.TrackRequest(id, "tools/call")

	method, ok := tracker.ResolveResponse(id)
	assert.True(t, ok)
	assert.Equal(t, "tools/call", method)
}

func TestRequestTrackerMultipleIDs(t *testing.T) {
	tracker := newRequestTracker()

	tracker.TrackRequest(json.RawMessage(`1`), "tools/list")
	tracker.TrackRequest(json.RawMessage(`2`), "tools/call")
	tracker.TrackRequest(json.RawMessage(`3`), "resources/list")

	method, ok := tracker.ResolveResponse(json.RawMessage(`2`))
	assert.True(t, ok)
	assert.Equal(t, "tools/call", method)

	method, ok = tracker.ResolveResponse(json.RawMessage(`1`))
	assert.True(t, ok)
	assert.Equal(t, "tools/list", method)

	method, ok = tracker.ResolveResponse(json.RawMessage(`3`))
	assert.True(t, ok)
	assert.Equal(t, "resources/list", method)
}

func TestRequestTrackerConcurrentAccess(t *testing.T) {
	tracker := newRequestTracker()
	const n = 100

	var wg sync.WaitGroup
	wg.Add(n * 2)

	// Concurrent TrackRequest
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			id := json.RawMessage(json.RawMessage(`"id-` + string(rune('A'+i%26)) + `"`))
			tracker.TrackRequest(id, "tools/list")
		}(i)
	}

	// Concurrent ResolveResponse
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			id := json.RawMessage(json.RawMessage(`"id-` + string(rune('A'+i%26)) + `"`))
			tracker.ResolveResponse(id) // may or may not find it; no panic = pass
		}(i)
	}

	wg.Wait()
	// If we get here without a race/panic, the test passes
}

// --- hashToolFull tests ---

func TestHashToolDeterministic(t *testing.T) {
	tool := MCPTool{
		Name:        "read_file",
		Description: "Reads a file from disk",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}`),
	}

	hash1, err := hashToolFull(tool)
	require.NoError(t, err)

	hash2, err := hashToolFull(tool)
	require.NoError(t, err)

	assert.Equal(t, hash1, hash2, "same tool should produce identical hash")
	assert.True(t, len(hash1) > 10, "hash should be non-trivial")
	assert.Contains(t, hash1, "sha256:", "hash should have sha256 prefix")
}

func TestHashToolReorderedJSONKeys(t *testing.T) {
	// Two tools with same content but different JSON key ordering in inputSchema.
	tool1 := MCPTool{
		Name:        "write_file",
		Description: "Writes content to a file",
		InputSchema: json.RawMessage(`{"type":"object","required":["path","content"],"properties":{"path":{"type":"string"},"content":{"type":"string"}}}`),
	}

	// Same schema with different key order.
	tool2 := MCPTool{
		Name:        "write_file",
		Description: "Writes content to a file",
		InputSchema: json.RawMessage(`{"properties":{"content":{"type":"string"},"path":{"type":"string"}},"required":["path","content"],"type":"object"}`),
	}

	hash1, err := hashToolFull(tool1)
	require.NoError(t, err)

	hash2, err := hashToolFull(tool2)
	require.NoError(t, err)

	assert.Equal(t, hash1, hash2, "same tool with reordered JSON keys should produce identical hash")
}

func TestHashToolDifferentDescriptions(t *testing.T) {
	tool1 := MCPTool{
		Name:        "read_file",
		Description: "Reads a file from disk",
		InputSchema: json.RawMessage(`{"type":"object"}`),
	}

	tool2 := MCPTool{
		Name:        "read_file",
		Description: "Reads a file from the filesystem",
		InputSchema: json.RawMessage(`{"type":"object"}`),
	}

	hash1, err := hashToolFull(tool1)
	require.NoError(t, err)

	hash2, err := hashToolFull(tool2)
	require.NoError(t, err)

	assert.NotEqual(t, hash1, hash2, "different descriptions should produce different hashes")
}

func TestHashToolDifferentSchemas(t *testing.T) {
	tool1 := MCPTool{
		Name:        "read_file",
		Description: "Reads a file",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"path":{"type":"string"}}}`),
	}

	tool2 := MCPTool{
		Name:        "read_file",
		Description: "Reads a file",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"path":{"type":"string"},"encoding":{"type":"string"}}}`),
	}

	hash1, err := hashToolFull(tool1)
	require.NoError(t, err)

	hash2, err := hashToolFull(tool2)
	require.NoError(t, err)

	assert.NotEqual(t, hash1, hash2, "different schemas should produce different hashes")
}

// --- ToolPinStore persistence tests ---

func TestToolPinStoreSaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	pinPath := filepath.Join(dir, "pins.json")

	// Create and populate store.
	store1 := NewToolPinStore(afero.NewOsFs(),pinPath)
	tool := MCPTool{
		Name:        "read_file",
		Description: "Reads a file from disk",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"path":{"type":"string"}}}`),
	}
	err := store1.Pin("server-1", tool)
	require.NoError(t, err)

	err = store1.Save()
	require.NoError(t, err)

	// Verify file exists and has restrictive permissions.
	info, err := os.Stat(pinPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm(), "pin file should have 0600 permissions")

	// Load into a new store and verify.
	store2 := NewToolPinStore(afero.NewOsFs(),pinPath)
	err = store2.Load()
	require.NoError(t, err)

	// Check should return no changes (same tool).
	changes, err := store2.Check("server-1", []MCPTool{tool}, false)
	require.NoError(t, err)
	assert.Empty(t, changes, "round-trip should produce no changes")
}

func TestToolPinStoreLoadNonExistentFile(t *testing.T) {
	dir := t.TempDir()
	pinPath := filepath.Join(dir, "nonexistent", "pins.json")

	store := NewToolPinStore(afero.NewOsFs(),pinPath)
	err := store.Load()
	assert.NoError(t, err, "loading non-existent file should not error")
}

func TestToolPinStoreRoundTripMultipleTools(t *testing.T) {
	dir := t.TempDir()
	pinPath := filepath.Join(dir, "pins.json")

	tools := []MCPTool{
		{Name: "read_file", Description: "Read", InputSchema: json.RawMessage(`{"type":"object"}`)},
		{Name: "write_file", Description: "Write", InputSchema: json.RawMessage(`{"type":"object"}`)},
		{Name: "delete_file", Description: "Delete", InputSchema: json.RawMessage(`{"type":"object"}`)},
	}

	store := NewToolPinStore(afero.NewOsFs(),pinPath)
	err := store.PinAll("server-a", tools)
	require.NoError(t, err)

	err = store.Save()
	require.NoError(t, err)

	store2 := NewToolPinStore(afero.NewOsFs(),pinPath)
	err = store2.Load()
	require.NoError(t, err)

	changes, err := store2.Check("server-a", tools, false)
	require.NoError(t, err)
	assert.Empty(t, changes)
}

// --- Between-session change detection tests ---

func TestToolPinStoreDetectsBetweenSessionDescriptionChange(t *testing.T) {
	dir := t.TempDir()
	pinPath := filepath.Join(dir, "pins.json")

	originalTool := MCPTool{
		Name:        "read_file",
		Description: "Reads a file from disk",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"path":{"type":"string"}}}`),
	}

	store := NewToolPinStore(afero.NewOsFs(),pinPath)
	err := store.Pin("server-1", originalTool)
	require.NoError(t, err)
	err = store.Save()
	require.NoError(t, err)

	// Reload and check with modified description.
	store2 := NewToolPinStore(afero.NewOsFs(),pinPath)
	err = store2.Load()
	require.NoError(t, err)

	modifiedTool := MCPTool{
		Name:        "read_file",
		Description: "Reads a file from the filesystem with improved error handling",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"path":{"type":"string"}}}`),
	}

	changes, err := store2.Check("server-1", []MCPTool{modifiedTool}, false)
	require.NoError(t, err)
	require.Len(t, changes, 1)
	assert.Equal(t, SeverityMedium, changes[0].Severity, "description-only change should be medium")
	assert.Equal(t, "read_file", changes[0].ToolName)
	assert.False(t, changes[0].MidSession)
	assert.Equal(t, "Reads a file from disk", changes[0].OldDesc)
	assert.Equal(t, "Reads a file from the filesystem with improved error handling", changes[0].NewDesc)
}

func TestToolPinStoreDetectsBetweenSessionSchemaChange(t *testing.T) {
	dir := t.TempDir()
	pinPath := filepath.Join(dir, "pins.json")

	originalTool := MCPTool{
		Name:        "read_file",
		Description: "Reads a file",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"path":{"type":"string"}}}`),
	}

	store := NewToolPinStore(afero.NewOsFs(),pinPath)
	err := store.Pin("server-1", originalTool)
	require.NoError(t, err)
	err = store.Save()
	require.NoError(t, err)

	store2 := NewToolPinStore(afero.NewOsFs(),pinPath)
	err = store2.Load()
	require.NoError(t, err)

	// Modified schema: added encoding parameter.
	modifiedTool := MCPTool{
		Name:        "read_file",
		Description: "Reads a file",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"path":{"type":"string"},"encoding":{"type":"string"}}}`),
	}

	changes, err := store2.Check("server-1", []MCPTool{modifiedTool}, false)
	require.NoError(t, err)
	require.Len(t, changes, 1)
	assert.Equal(t, SeverityHigh, changes[0].Severity, "schema change should be high severity")
}

// --- Mid-session rug-pull detection tests ---

func TestToolPinStoreDetectsMidSessionToolAddition(t *testing.T) {
	store := NewToolPinStore(afero.NewOsFs(),"")

	originalTools := []MCPTool{
		{Name: "read_file", Description: "Read", InputSchema: json.RawMessage(`{"type":"object"}`)},
	}

	// Pin and set baseline.
	err := store.PinAll("server-1", originalTools)
	require.NoError(t, err)
	store.SetSessionBaseline("server-1", originalTools)

	// New tools list has an addition.
	newTools := []MCPTool{
		{Name: "read_file", Description: "Read", InputSchema: json.RawMessage(`{"type":"object"}`)},
		{Name: "exec_command", Description: "Execute arbitrary command", InputSchema: json.RawMessage(`{"type":"object"}`)},
	}

	changes, err := store.Check("server-1", newTools, true)
	require.NoError(t, err)
	require.Len(t, changes, 1)
	assert.Equal(t, "exec_command", changes[0].ToolName)
	assert.Equal(t, SeverityCritical, changes[0].Severity, "mid-session tool addition should be critical")
	assert.True(t, changes[0].MidSession)
}

func TestToolPinStoreDetectsMidSessionToolRemoval(t *testing.T) {
	store := NewToolPinStore(afero.NewOsFs(),"")

	originalTools := []MCPTool{
		{Name: "read_file", Description: "Read", InputSchema: json.RawMessage(`{"type":"object"}`)},
		{Name: "write_file", Description: "Write", InputSchema: json.RawMessage(`{"type":"object"}`)},
	}

	err := store.PinAll("server-1", originalTools)
	require.NoError(t, err)
	store.SetSessionBaseline("server-1", originalTools)

	// Tool removed mid-session.
	newTools := []MCPTool{
		{Name: "read_file", Description: "Read", InputSchema: json.RawMessage(`{"type":"object"}`)},
	}

	changes, err := store.Check("server-1", newTools, true)
	require.NoError(t, err)
	require.Len(t, changes, 1)
	assert.Equal(t, "write_file", changes[0].ToolName)
	assert.Equal(t, SeverityCritical, changes[0].Severity, "mid-session tool removal should be critical")
	assert.True(t, changes[0].MidSession)
}

func TestToolPinStoreDetectsMidSessionSchemaChange(t *testing.T) {
	store := NewToolPinStore(afero.NewOsFs(),"")

	originalTools := []MCPTool{
		{Name: "read_file", Description: "Read", InputSchema: json.RawMessage(`{"type":"object","properties":{"path":{"type":"string"}}}`)},
	}

	err := store.PinAll("server-1", originalTools)
	require.NoError(t, err)
	store.SetSessionBaseline("server-1", originalTools)

	// Schema changed mid-session.
	newTools := []MCPTool{
		{Name: "read_file", Description: "Read", InputSchema: json.RawMessage(`{"type":"object","properties":{"path":{"type":"string"},"command":{"type":"string"}}}`)},
	}

	changes, err := store.Check("server-1", newTools, true)
	require.NoError(t, err)
	require.Len(t, changes, 1)
	assert.Equal(t, SeverityHigh, changes[0].Severity, "mid-session schema change should be high")
	assert.True(t, changes[0].MidSession)
}

func TestToolPinStoreNoMidSessionChanges(t *testing.T) {
	store := NewToolPinStore(afero.NewOsFs(),"")

	tools := []MCPTool{
		{Name: "read_file", Description: "Read", InputSchema: json.RawMessage(`{"type":"object"}`)},
	}

	err := store.PinAll("server-1", tools)
	require.NoError(t, err)
	store.SetSessionBaseline("server-1", tools)

	// Same tools.
	changes, err := store.Check("server-1", tools, true)
	require.NoError(t, err)
	assert.Empty(t, changes)
}

// --- Accept tests ---

func TestToolPinStoreAcceptUpdatesPinEntry(t *testing.T) {
	dir := t.TempDir()
	pinPath := filepath.Join(dir, "pins.json")

	originalTool := MCPTool{
		Name:        "read_file",
		Description: "Original description",
		InputSchema: json.RawMessage(`{"type":"object"}`),
	}

	store := NewToolPinStore(afero.NewOsFs(),pinPath)
	err := store.Pin("server-1", originalTool)
	require.NoError(t, err)

	// Modify and accept.
	newTool := MCPTool{
		Name:        "read_file",
		Description: "Updated description with new semantics",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"encoding":{"type":"string"}}}`),
	}

	err = store.Accept("server-1", "read_file", newTool)
	require.NoError(t, err)

	// Check should show no changes now.
	changes, err := store.Check("server-1", []MCPTool{newTool}, false)
	require.NoError(t, err)
	assert.Empty(t, changes, "accepted change should not trigger pin change")
}

// --- classifyPinChange tests ---

func TestClassifyPinChangeSchemaChange(t *testing.T) {
	old := &PinEntry{
		DescriptionHash: "sha256:aaa",
		SchemaHash:      "sha256:bbb",
		FullHash:        "sha256:ccc",
		Description:     "Original",
	}

	newTool := MCPTool{
		Name:        "test",
		Description: "Original",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"newParam":{"type":"string"}}}`),
	}

	severity := classifyPinChange(old, newTool, false)
	assert.Equal(t, SeverityHigh, severity, "schema change should be high")
}

func TestClassifyPinChangeDescriptionChange(t *testing.T) {
	descBytes, _ := json.Marshal("Original")
	descHash := hashField(descBytes)
	schemaHash := hashField([]byte(`{"type":"object"}`))

	old := &PinEntry{
		DescriptionHash: descHash,
		SchemaHash:      schemaHash,
		FullHash:        "sha256:ccc",
		Description:     "Original",
	}

	newTool := MCPTool{
		Name:        "test",
		Description: "Modified description",
		InputSchema: json.RawMessage(`{"type":"object"}`),
	}

	severity := classifyPinChange(old, newTool, false)
	assert.Equal(t, SeverityMedium, severity, "description-only change should be medium")
}

func TestClassifyPinChangeNilOldMidSession(t *testing.T) {
	newTool := MCPTool{
		Name:        "new_tool",
		Description: "Newly added",
		InputSchema: json.RawMessage(`{"type":"object"}`),
	}

	severity := classifyPinChange(nil, newTool, true)
	assert.Equal(t, SeverityCritical, severity, "nil old entry mid-session should be critical")
}

func TestClassifyPinChangeNilOldBetweenSession(t *testing.T) {
	newTool := MCPTool{
		Name:        "new_tool",
		Description: "Newly added",
		InputSchema: json.RawMessage(`{"type":"object"}`),
	}

	severity := classifyPinChange(nil, newTool, false)
	assert.Equal(t, SeverityMedium, severity, "nil old entry between-session should be medium (new tool)")
}

// --- Pin file format tests ---

func TestToolPinStorePinFileFormat(t *testing.T) {
	dir := t.TempDir()
	pinPath := filepath.Join(dir, "pins.json")

	store := NewToolPinStore(afero.NewOsFs(),pinPath)
	tool := MCPTool{
		Name:        "read_file",
		Description: "Reads files",
		InputSchema: json.RawMessage(`{"type":"object"}`),
	}
	err := store.Pin("server-1", tool)
	require.NoError(t, err)
	err = store.Save()
	require.NoError(t, err)

	// Read raw file and verify format.
	data, err := os.ReadFile(pinPath)
	require.NoError(t, err)

	var pf PinFile
	err = json.Unmarshal(data, &pf)
	require.NoError(t, err)

	assert.Equal(t, 1, pf.Version, "pin file version should be 1")
	assert.Contains(t, pf.Pins, "server-1::read_file", "pin key should be serverID::toolName")

	entry := pf.Pins["server-1::read_file"]
	assert.Contains(t, entry.FullHash, "sha256:", "full hash should have sha256 prefix")
	assert.Contains(t, entry.DescriptionHash, "sha256:", "description hash should have sha256 prefix")
	assert.Contains(t, entry.SchemaHash, "sha256:", "schema hash should have sha256 prefix")
	assert.Equal(t, "Reads files", entry.Description)
	assert.False(t, entry.PinnedAt.IsZero())
	assert.False(t, entry.LastVerified.IsZero())
}

// --- Empty pin store (first connection) tests ---

func TestToolPinStoreFirstConnectionPinsAllTools(t *testing.T) {
	dir := t.TempDir()
	pinPath := filepath.Join(dir, "pins.json")

	store := NewToolPinStore(afero.NewOsFs(),pinPath)

	tools := []MCPTool{
		{Name: "read_file", Description: "Read", InputSchema: json.RawMessage(`{"type":"object"}`)},
		{Name: "write_file", Description: "Write", InputSchema: json.RawMessage(`{"type":"object"}`)},
	}

	// On first connection, Check returns no changes for new tools.
	changes, err := store.Check("server-1", tools, false)
	require.NoError(t, err)
	assert.Empty(t, changes, "first connection should report no changes")

	// Pin all tools.
	err = store.PinAll("server-1", tools)
	require.NoError(t, err)

	// Verify they are pinned.
	changes, err = store.Check("server-1", tools, false)
	require.NoError(t, err)
	assert.Empty(t, changes)
}

// --- Multiple servers isolation test ---

func TestToolPinStoreIsolatesServers(t *testing.T) {
	store := NewToolPinStore(afero.NewOsFs(),"")

	tool := MCPTool{
		Name:        "read_file",
		Description: "Read",
		InputSchema: json.RawMessage(`{"type":"object"}`),
	}

	err := store.Pin("server-a", tool)
	require.NoError(t, err)

	// Different server with modified tool should not see changes.
	modifiedTool := MCPTool{
		Name:        "read_file",
		Description: "Read from server B with different behavior",
		InputSchema: json.RawMessage(`{"type":"object"}`),
	}

	// server-b has no pins, so no changes detected.
	changes, err := store.Check("server-b", []MCPTool{modifiedTool}, false)
	require.NoError(t, err)
	assert.Empty(t, changes)

	// server-a check with original tool should show no changes.
	changes, err = store.Check("server-a", []MCPTool{tool}, false)
	require.NoError(t, err)
	assert.Empty(t, changes)
}
