package skillledger.policy

import rego.v1

default decision := "allow"

deny := set()
warnings := set()
