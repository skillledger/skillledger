package skillledger.runtime_policy

import rego.v1

default decision := "allow"

# Warn on undeclared HTTP destinations (moderate does not block destinations)
warnings contains msg if {
    input.action.type == "http_request"
    dest := input.action.destination
    not dest_in_manifest(dest)
    msg := sprintf("undeclared destination: %s", [dest])
}

# Block undeclared MCP tools
deny contains msg if {
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
