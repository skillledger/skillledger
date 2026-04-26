package skillledger.runtime_policy

import rego.v1

default decision := "allow"

deny := set()

# Warn on undeclared MCP tools
warnings contains msg if {
    input.action.type == "mcp_tool_call"
    tool := input.action.tool
    not tool in input.manifest.capabilities.tools
    msg := sprintf("undeclared tool: %s", [tool])
}

# Log undeclared destinations (use "log:" prefix for log-level warnings)
warnings contains msg if {
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
