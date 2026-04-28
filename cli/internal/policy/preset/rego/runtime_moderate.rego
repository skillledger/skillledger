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

# --- Unverified lockdown rules (same as strict -- lockdown is universal per CONTEXT.md) ---

# Unverified lockdown: block ALL non-localhost HTTP regardless of manifest
deny contains msg if {
    trust_tier == "unverified"
    input.action.type == "http_request"
    dest := input.action.destination
    not is_localhost(dest)
    msg := sprintf("unverified skill: blocked non-localhost destination %s", [dest])
}

# Unverified lockdown: block ALL MCP tool calls not in manifest
deny contains msg if {
    trust_tier == "unverified"
    input.action.type == "mcp_tool_call"
    tool := input.action.tool
    not tool in input.manifest.capabilities.tools
    msg := sprintf("unverified skill: blocked undeclared tool %s", [tool])
}

# --- Partial rules (moderate warns on all partial actions) ---

# Partial: warn on all actions
warnings contains msg if {
    trust_tier == "partial"
    msg := sprintf("partially verified skill action: %s %s", [input.action.type, input.action.destination])
}

# --- Standard moderate rules (apply when not in lockdown) ---

# Warn on undeclared HTTP destinations (moderate does not block destinations for verified)
warnings contains msg if {
    not trust_tier == "unverified"
    not trust_tier == "partial"
    input.action.type == "http_request"
    dest := input.action.destination
    not dest_in_manifest(dest)
    msg := sprintf("undeclared destination: %s", [dest])
}

# Block undeclared MCP tools
deny contains msg if {
    not trust_tier == "unverified"
    input.action.type == "mcp_tool_call"
    tool := input.action.tool
    not tool in input.manifest.capabilities.tools
    msg := sprintf("undeclared tool: %s", [tool])
}

# Block undeclared MCP resources
deny contains msg if {
    input.action.type == "mcp_resource_access"
    resource := input.action.resource
    not resource_in_manifest(resource)
    msg := sprintf("undeclared resource: %s", [resource])
}

# Helper: check if destination matches any declared network capability
dest_in_manifest(dest) if {
    some cap in input.manifest.capabilities.network
    glob.match(cap, ["."], dest)
}

# Helper: check if resource matches any declared tool
resource_in_manifest(resource) if {
    some cap in input.manifest.capabilities.tools
    glob.match(cap, ["/"], resource)
}

decision := "deny" if {
    count(deny) > 0
}

decision := "warn" if {
    count(deny) == 0
    count(warnings) > 0
}
