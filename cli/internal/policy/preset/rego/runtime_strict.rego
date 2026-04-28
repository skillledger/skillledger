package skillledger.runtime_policy

import rego.v1

default decision := "deny"

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

# --- Unverified lockdown rules ---

# Unverified: allow localhost HTTP (override the general deny)
unverified_localhost if {
    trust_tier == "unverified"
    input.action.type == "http_request"
    is_localhost(input.action.destination)
}

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

# --- Partial rules (strict blocks partial undeclared too) ---

# Partial: block undeclared HTTP destinations
deny contains msg if {
    trust_tier == "partial"
    input.action.type == "http_request"
    dest := input.action.destination
    not dest_in_manifest(dest)
    msg := sprintf("partially verified skill: blocked undeclared destination %s", [dest])
}

# --- Standard strict rules (apply to verified and any tier for undeclared) ---

# Block any HTTP destination not declared in manifest (for verified/unknown tiers)
deny contains msg if {
    not trust_tier == "unverified"
    not trust_tier == "partial"
    input.action.type == "http_request"
    dest := input.action.destination
    not dest_in_manifest(dest)
    msg := sprintf("undeclared destination: %s", [dest])
}

# Block any MCP tool not declared in manifest
deny contains msg if {
    not trust_tier == "unverified"
    input.action.type == "mcp_tool_call"
    tool := input.action.tool
    not tool in input.manifest.capabilities.tools
    msg := sprintf("undeclared tool: %s", [tool])
}

# Block any MCP resource not declared (strict blocks everything undeclared)
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

warnings := set()

# Allow if no denials -- special case for unverified localhost
decision := "allow" if {
    unverified_localhost
    count(deny) == 0
}

decision := "allow" if {
    not unverified_localhost
    count(deny) == 0
}
