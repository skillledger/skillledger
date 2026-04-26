package proxy

// RuntimeAction represents a single action intercepted by the proxy for a skill.
type RuntimeAction struct {
	SkillID     string
	ActionType  string // "http_request", "mcp_tool_call", "mcp_resource_access"
	Destination string
	Method      string
	ToolName    string
	Resource    string
}

// ActionObserver receives runtime actions for observation or enforcement.
type ActionObserver interface {
	Observe(action RuntimeAction)
}
