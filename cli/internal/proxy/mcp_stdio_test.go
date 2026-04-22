package proxy_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/skillledger/skillledger/internal/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMCPWrapper_RelayInspection(t *testing.T) {
	dl := proxy.NewDecisionLog(100)
	logger := zerolog.Nop()

	// Use "cat" as the child process -- it echoes stdin to stdout.
	wrapper, err := proxy.NewMCPWrapper("cat", nil, "test-mcp-server", dl, logger)
	require.NoError(t, err)

	// Prepare a valid JSON-RPC message.
	jsonRPC := `{"jsonrpc":"2.0","method":"tools/list","id":1}` + "\n"
	input := strings.NewReader(jsonRPC)
	var output bytes.Buffer

	err = wrapper.RunWithStreams(input, &output)
	require.NoError(t, err)

	// Verify message was forwarded intact.
	assert.Contains(t, output.String(), `"jsonrpc":"2.0"`)
	assert.Contains(t, output.String(), `"tools/list"`)

	// DecisionLog should have 2 entries: one for request (agent->server),
	// one for response (server->agent, since cat echoes back).
	assert.Equal(t, 2, dl.Count())
	entries := dl.Recent(2)
	require.Len(t, entries, 2)

	// Find the request-direction entry (order may vary due to goroutines).
	var reqEntry, respEntry proxy.DecisionEntry
	for _, e := range entries {
		if e.Direction == "request" {
			reqEntry = e
		} else {
			respEntry = e
		}
	}
	assert.Equal(t, "tools/list", reqEntry.Method)
	assert.Equal(t, "request", reqEntry.Direction)
	assert.Equal(t, proxy.ActionAllow, reqEntry.Decision)
	assert.Equal(t, "mcp-stdio", reqEntry.Protocol)
	assert.Equal(t, "test-mcp-server", reqEntry.SkillID)
	assert.Contains(t, reqEntry.Reason, "passthrough")

	assert.Equal(t, "tools/list", respEntry.Method)
	assert.Equal(t, "response", respEntry.Direction)
}

func TestMCPWrapper_NonJSONRPC(t *testing.T) {
	dl := proxy.NewDecisionLog(100)
	logger := zerolog.Nop()

	wrapper, err := proxy.NewMCPWrapper("cat", nil, "test-mcp-server", dl, logger)
	require.NoError(t, err)

	// Send a non-JSON-RPC line.
	input := strings.NewReader("hello world\n")
	var output bytes.Buffer

	err = wrapper.RunWithStreams(input, &output)
	require.NoError(t, err)

	// Verify line was forwarded (not dropped).
	assert.Contains(t, output.String(), "hello world")

	// Non-JSON-RPC lines should not create decision entries.
	assert.Equal(t, 0, dl.Count())
}

func TestMCPWrapper_LargeMessage(t *testing.T) {
	dl := proxy.NewDecisionLog(100)
	logger := zerolog.Nop()

	wrapper, err := proxy.NewMCPWrapper("cat", nil, "test-mcp-server", dl, logger)
	require.NoError(t, err)

	// Create a JSON-RPC message > 16KB (exceeding macOS pipe buffer).
	// The params field contains a large string to push beyond 16KB.
	largeValue := strings.Repeat("x", 20000)
	jsonRPC := `{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"data":"` + largeValue + `"}}` + "\n"
	input := strings.NewReader(jsonRPC)
	var output bytes.Buffer

	err = wrapper.RunWithStreams(input, &output)
	require.NoError(t, err)

	// Verify the large message was forwarded completely without truncation.
	assert.Contains(t, output.String(), largeValue)
	assert.True(t, len(output.String()) > 20000, "output should be larger than 20KB")

	// Verify it was parsed as JSON-RPC (2 entries: request + echoed response).
	assert.Equal(t, 2, dl.Count())
	entries := dl.Recent(2)
	require.Len(t, entries, 2)
	// Both entries should have the same method.
	assert.Equal(t, "tools/call", entries[0].Method)
	assert.Equal(t, "tools/call", entries[1].Method)
}

func TestStreamableProxy_Creation(t *testing.T) {
	dl := proxy.NewDecisionLog(100)
	logger := zerolog.Nop()

	sp := proxy.NewStreamableProxy("ws://localhost:8080/mcp", dl, logger)
	require.NotNil(t, sp)
}
