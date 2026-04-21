package proxy_test

import (
	"strings"
	"testing"

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
