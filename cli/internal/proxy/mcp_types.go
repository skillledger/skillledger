package proxy

import (
	"encoding/json"
	"fmt"
)

// MCPTool represents a single tool from the MCP tools/list response.
// Fields match the MCP 2025-11-25 specification.
type MCPTool struct {
	Name        string          `json:"name"`
	Title       string          `json:"title,omitempty"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
	Annotations json.RawMessage `json:"annotations,omitempty"`
}

// MCPToolsListResult is the result field of a tools/list JSON-RPC response.
type MCPToolsListResult struct {
	Tools      []MCPTool `json:"tools"`
	NextCursor string    `json:"nextCursor,omitempty"`
}

// MCPToolCallResult is the result field of a tools/call JSON-RPC response.
type MCPToolCallResult struct {
	Content []MCPContent `json:"content"`
	IsError bool         `json:"isError"`
}

// MCPContent represents a single content item in an MCP tool call result.
type MCPContent struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
	Data string `json:"data,omitempty"`
}

// parseToolsList parses the result field of a tools/list JSON-RPC response
// into a slice of MCPTool.
func parseToolsList(result json.RawMessage) ([]MCPTool, error) {
	var r MCPToolsListResult
	if err := json.Unmarshal(result, &r); err != nil {
		return nil, fmt.Errorf("parse tools/list result: %w", err)
	}
	return r.Tools, nil
}

// extractTextFromToolResult extracts all text content from a tools/call result
// where the content type is "text" and the text is longer than 50 characters.
// Per CONTEXT.md: scan applies to text fields > 50 chars in tool output.
func extractTextFromToolResult(result json.RawMessage) []string {
	var r MCPToolCallResult
	if err := json.Unmarshal(result, &r); err != nil {
		return nil
	}
	var texts []string
	for _, c := range r.Content {
		if c.Type == "text" && len(c.Text) > 50 {
			texts = append(texts, c.Text)
		}
	}
	return texts
}
