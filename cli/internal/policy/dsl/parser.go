package dsl

import (
	"fmt"
	"strings"

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
			if r.Message == "" {
				return nil, fmt.Errorf("rule %s[%d]: message field is required", category, i)
			}
		}
	}

	if p.RuntimeRules != nil {
		for i, expr := range p.RuntimeRules.Block {
			if strings.TrimSpace(expr) == "" {
				return nil, fmt.Errorf("runtime-rules.block[%d]: empty expression", i)
			}
		}
		for i, expr := range p.RuntimeRules.Warn {
			if strings.TrimSpace(expr) == "" {
				return nil, fmt.Errorf("runtime-rules.warn[%d]: empty expression", i)
			}
		}
		for i, expr := range p.RuntimeRules.Log {
			if strings.TrimSpace(expr) == "" {
				return nil, fmt.Errorf("runtime-rules.log[%d]: empty expression", i)
			}
		}
	}

	return &p, nil
}
