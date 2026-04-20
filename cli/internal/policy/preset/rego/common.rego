package skillledger.policy

import rego.v1

# Common decision logic shared by presets.
# Each preset defines its own deny and warnings sets.
# Decision precedence: deny > warn > allow.
