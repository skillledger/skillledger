package dsl

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// Parse parses a YAML policy DSL file and returns a typed Policy.
func Parse(data []byte) (*Policy, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("policy data is empty")
	}

	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("YAML parse error: %w", err)
	}

	if p.Version != 1 {
		return nil, fmt.Errorf("unsupported policy version: %d (expected 1)", p.Version)
	}

	if len(p.Rules) == 0 {
		return nil, fmt.Errorf("policy must contain at least one rule")
	}

	for category, rules := range p.Rules {
		for i, r := range rules {
			hasDeny := r.Deny != ""
			hasWarn := r.Warn != ""
			if hasDeny == hasWarn {
				return nil, fmt.Errorf("rule %s[%d]: exactly one of deny or warn must be set", category, i)
			}
		}
	}

	return &p, nil
}
