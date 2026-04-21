package proxy

import (
	"encoding/json"
	"fmt"
)

const (
	// ProtocolVersion is the SkillLedger proxy protocol version.
	ProtocolVersion = "v1"
	// ProtocolHeader is the HTTP header used to identify proxy-intercepted traffic.
	ProtocolHeader = "X-SkillLedger-Proxy"
)

// JSONRPCMessage represents a JSON-RPC 2.0 message (request, response, or notification).
type JSONRPCMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

// ParseJSONRPC unmarshals a JSON-RPC 2.0 message and validates the version field.
func ParseJSONRPC(data []byte) (*JSONRPCMessage, error) {
	var msg JSONRPCMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, fmt.Errorf("parse JSON-RPC: %w", err)
	}
	if msg.JSONRPC != "2.0" {
		return nil, fmt.Errorf("unsupported JSON-RPC version: %q (expected \"2.0\")", msg.JSONRPC)
	}
	return &msg, nil
}

// IsRequest returns true if the message is a JSON-RPC request (has method, no result/error).
func (m *JSONRPCMessage) IsRequest() bool {
	return m.Method != "" && m.Result == nil && m.Error == nil && m.ID != nil
}

// IsResponse returns true if the message is a JSON-RPC response (has result or error).
func (m *JSONRPCMessage) IsResponse() bool {
	return m.Result != nil || m.Error != nil
}

// IsNotification returns true if the message is a JSON-RPC notification (has method, no ID).
func (m *JSONRPCMessage) IsNotification() bool {
	return m.Method != "" && m.ID == nil
}
