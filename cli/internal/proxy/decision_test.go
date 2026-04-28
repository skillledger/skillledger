package proxy_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/skillledger/skillledger/internal/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecisionLog_RecordAndLookup(t *testing.T) {
	dl := proxy.NewDecisionLog(10)

	ids := make([]string, 3)
	for i := 0; i < 3; i++ {
		id := proxy.NewActionID()
		ids[i] = id
		dl.Record(proxy.DecisionEntry{
			ActionID:  id,
			Direction: "request",
			Decision:  proxy.ActionAllow,
			Reason:    "test",
		})
	}

	for _, id := range ids {
		entry, found := dl.Lookup(id)
		require.True(t, found, "expected to find %s", id)
		assert.Equal(t, id, entry.ActionID)
	}
}

func TestDecisionLog_RingBufferWrap(t *testing.T) {
	dl := proxy.NewDecisionLog(3)

	ids := make([]string, 5)
	for i := 0; i < 5; i++ {
		id := proxy.NewActionID()
		ids[i] = id
		dl.Record(proxy.DecisionEntry{
			ActionID:  id,
			Direction: "request",
			Decision:  proxy.ActionLog,
			Reason:    "wrap test",
		})
	}

	// Only last 3 should be accessible
	recent := dl.Recent(10)
	require.Len(t, recent, 3)

	// First 2 should be evicted
	_, found := dl.Lookup(ids[0])
	assert.False(t, found)
	_, found = dl.Lookup(ids[1])
	assert.False(t, found)

	// Last 3 should be present
	for _, id := range ids[2:] {
		_, found := dl.Lookup(id)
		assert.True(t, found, "expected to find %s", id)
	}
}

func TestDecisionLog_AutoGenerateID(t *testing.T) {
	dl := proxy.NewDecisionLog(10)
	dl.Record(proxy.DecisionEntry{
		Direction: "request",
		Decision:  proxy.ActionBlock,
		Reason:    "auto-id test",
	})

	recent := dl.Recent(1)
	require.Len(t, recent, 1)
	assert.True(t, strings.HasPrefix(recent[0].ActionID, "act-"))

	// Should be findable by the generated ID
	entry, found := dl.Lookup(recent[0].ActionID)
	require.True(t, found)
	assert.Equal(t, proxy.ActionBlock, entry.Decision)
}

func TestDecisionLog_AutoTimestamp(t *testing.T) {
	dl := proxy.NewDecisionLog(10)
	dl.Record(proxy.DecisionEntry{
		ActionID:  "act-ts-test",
		Direction: "response",
		Decision:  proxy.ActionWarn,
		Reason:    "timestamp test",
	})

	entry, found := dl.Lookup("act-ts-test")
	require.True(t, found)
	assert.False(t, entry.Timestamp.IsZero())
}

func TestDecisionLog_Recent(t *testing.T) {
	dl := proxy.NewDecisionLog(10)

	ids := make([]string, 5)
	for i := 0; i < 5; i++ {
		id := proxy.NewActionID()
		ids[i] = id
		dl.Record(proxy.DecisionEntry{
			ActionID:  id,
			Direction: "request",
			Decision:  proxy.ActionAllow,
			Reason:    "recent test",
		})
	}

	recent := dl.Recent(3)
	require.Len(t, recent, 3)
	// Should be in reverse chronological order (newest first)
	assert.Equal(t, ids[4], recent[0].ActionID)
	assert.Equal(t, ids[3], recent[1].ActionID)
	assert.Equal(t, ids[2], recent[2].ActionID)
}

func TestParseJSONRPC_Request(t *testing.T) {
	data := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)
	msg, err := proxy.ParseJSONRPC(data)
	require.NoError(t, err)
	assert.True(t, msg.IsRequest())
	assert.False(t, msg.IsResponse())
	assert.False(t, msg.IsNotification())
	assert.Equal(t, "tools/list", msg.Method)
}

func TestParseJSONRPC_Response(t *testing.T) {
	data := []byte(`{"jsonrpc":"2.0","id":1,"result":{}}`)
	msg, err := proxy.ParseJSONRPC(data)
	require.NoError(t, err)
	assert.True(t, msg.IsResponse())
	assert.False(t, msg.IsRequest())
}

func TestParseJSONRPC_Notification(t *testing.T) {
	data := []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	msg, err := proxy.ParseJSONRPC(data)
	require.NoError(t, err)
	assert.True(t, msg.IsNotification())
	assert.False(t, msg.IsRequest())
	assert.False(t, msg.IsResponse())
}

func TestParseJSONRPC_InvalidVersion(t *testing.T) {
	data := []byte(`{"jsonrpc":"1.0","method":"test"}`)
	_, err := proxy.ParseJSONRPC(data)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported JSON-RPC version")
}

func TestNewActionID(t *testing.T) {
	id1 := proxy.NewActionID()
	id2 := proxy.NewActionID()
	assert.True(t, strings.HasPrefix(id1, "act-"))
	assert.True(t, strings.HasPrefix(id2, "act-"))
	assert.NotEqual(t, id1, id2)
}

func TestDecisionEntryWithFindings_MarshalJSON(t *testing.T) {
	entry := proxy.DecisionEntry{
		ActionID:  "act-12345678",
		Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Direction: "request",
		Decision:  proxy.ActionWarn,
		Reason:    "[high] secret: API key detected",
		Findings: []proxy.Finding{
			{
				Scanner:     "secret",
				Severity:    "high",
				Description: "API key detected",
				Decision:    proxy.ActionWarn,
			},
		},
	}

	data, err := json.Marshal(entry)
	require.NoError(t, err)

	var raw map[string]json.RawMessage
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)
	assert.Contains(t, raw, "findings", "JSON should contain 'findings' key when findings are present")
}

func TestDecisionEntryWithoutFindings_MarshalJSON(t *testing.T) {
	entry := proxy.DecisionEntry{
		ActionID:  "act-12345678",
		Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Direction: "request",
		Decision:  proxy.ActionAllow,
		Reason:    "no findings",
	}

	data, err := json.Marshal(entry)
	require.NoError(t, err)

	var raw map[string]json.RawMessage
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)
	assert.NotContains(t, raw, "findings", "JSON should NOT contain 'findings' key when findings are nil")
}

func TestDecisionEntryOldFormat_UnmarshalJSON(t *testing.T) {
	oldJSON := `{"action_id":"act-00000001","timestamp":"2026-01-01T00:00:00Z","direction":"request","decision":"allow","reason":"no findings"}`

	var entry proxy.DecisionEntry
	err := json.Unmarshal([]byte(oldJSON), &entry)
	require.NoError(t, err)

	assert.Equal(t, "act-00000001", entry.ActionID)
	assert.Equal(t, proxy.ActionAllow, entry.Decision)
	assert.Nil(t, entry.Findings, "Findings should be nil for old format entries")
}

func TestDecisionEntryFindings_RoundTrip(t *testing.T) {
	original := proxy.DecisionEntry{
		ActionID:  "act-roundtrip",
		Timestamp: time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC),
		Direction: "request",
		Decision:  proxy.ActionBlock,
		Reason:    "multiple findings",
		Findings: []proxy.Finding{
			{Scanner: "secret", Severity: "critical", Description: "AWS key", Decision: proxy.ActionBlock},
			{Scanner: "network", Severity: "high", Description: "Malicious host", Decision: proxy.ActionWarn},
		},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded proxy.DecisionEntry
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.ActionID, decoded.ActionID)
	assert.Equal(t, original.Decision, decoded.Decision)
	require.Len(t, decoded.Findings, 2)
	assert.Equal(t, "secret", decoded.Findings[0].Scanner)
	assert.Equal(t, "critical", decoded.Findings[0].Severity)
	assert.Equal(t, "network", decoded.Findings[1].Scanner)
}
