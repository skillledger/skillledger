package proxy

import (
	"encoding/json"
	"sync"
	"testing"

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
