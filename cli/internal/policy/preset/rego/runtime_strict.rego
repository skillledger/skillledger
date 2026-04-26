package skillledger.runtime_policy

import rego.v1

default decision := "deny"

# Block any HTTP destination not declared in manifest network capabilities
deny contains msg if {
    input.action.type == "http_request"
    dest := input.action.destination
    not dest_in_manifest(dest)
    msg := sprintf("undeclared destination: %s", [dest])
}

# Block any MCP tool not declared in manifest
deny contains msg if {
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

decision := "allow" if {
    count(deny) == 0
}
