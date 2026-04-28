package skillledger.runtime_policy

import rego.v1

default decision := "allow"

# Default trust_tier to "unverified" if absent (backward compatibility / fail-closed)
default trust_tier := "unverified"

trust_tier := input.trust_tier

# Helper: check if destination is localhost
is_localhost(dest) if {
    startswith(dest, "localhost")
}

is_localhost(dest) if {
    startswith(dest, "127.0.0.1")
}

is_localhost(dest) if {
    startswith(dest, "::1")
}

deny := set()

# --- Unverified rules (permissive warns instead of blocking per CONTEXT.md) ---

# Unverified: warn on non-localhost HTTP (not block)
warnings contains msg if {
    trust_tier == "unverified"
    input.action.type == "http_request"
    dest := input.action.destination
    not is_localhost(dest)
    msg := sprintf("unverified skill: non-localhost destination %s", [dest])
}

# Unverified: warn on undeclared MCP tools
warnings contains msg if {
    trust_tier == "unverified"
    input.action.type == "mcp_tool_call"
    tool := input.action.tool
    not tool in input.manifest.capabilities.tools
    msg := sprintf("unverified skill: undeclared tool %s", [tool])
}

# --- Partial rules (warn on all actions) ---

# Partial: warn on all actions
warnings contains msg if {
    trust_tier == "partial"
    msg := sprintf("partially verified skill action: %s %s", [input.action.type, input.action.destination])
}

# --- Standard permissive rules ---

# Warn on undeclared MCP tools (for verified/unknown tiers)
warnings contains msg if {
    not trust_tier == "unverified"
    not trust_tier == "partial"
    input.action.type == "mcp_tool_call"
    tool := input.action.tool
    not tool in input.manifest.capabilities.tools
    msg := sprintf("undeclared tool: %s", [tool])
}

# Log undeclared destinations (use "log:" prefix for log-level warnings)
warnings contains msg if {
    not trust_tier == "unverified"
    not trust_tier == "partial"
    input.action.type == "http_request"
    dest := input.action.destination
    not dest_in_manifest(dest)
    msg := sprintf("log: undeclared destination: %s", [dest])
}

# Helper: check if destination matches any declared network capability
dest_in_manifest(dest) if {
    some cap in input.manifest.capabilities.network
    glob.match(cap, ["."], dest)
}

decision := "warn" if {
    count(deny) == 0
    count(warnings) > 0
}
