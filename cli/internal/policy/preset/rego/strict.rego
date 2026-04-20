package skillledger.policy

import rego.v1

default decision := "deny"

deny contains "filesystem write access not permitted" if {
	some cap in input.capabilities.filesystem
	contains(cap, "write")
}

deny contains "network access not permitted" if {
	some cap in input.capabilities.network
	startswith(cap, "outbound")
}

deny contains "inbound network access not permitted" if {
	some cap in input.capabilities.network
	startswith(cap, "inbound")
}

deny contains "secrets access not permitted" if {
	count(input.capabilities.secrets) > 0
}

deny contains "tool execution not permitted" if {
	count(input.capabilities.tools) > 0
}

warnings := set()

decision := "allow" if {
	count(deny) == 0
}
