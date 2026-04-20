package skillledger.policy

import rego.v1

default decision := "allow"

warnings contains "filesystem write access detected" if {
	some cap in input.capabilities.filesystem
	contains(cap, "write")
}

deny contains "unrestricted network access not permitted" if {
	some cap in input.capabilities.network
	cap == "outbound"
}

deny contains "vault secrets access not permitted" if {
	some cap in input.capabilities.secrets
	startswith(cap, "vault")
}

warnings contains msg if {
	some cap in input.capabilities.tools
	cap != "execute:python"
	msg := sprintf("non-python tool execution: %s", [cap])
}

decision := "deny" if count(deny) > 0

decision := "warn" if {
	count(deny) == 0
	count(warnings) > 0
}
