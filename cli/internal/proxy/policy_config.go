package proxy

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// PolicyConfig controls how violation types map to proxy response actions.
type PolicyConfig struct {
	Preset          string            `yaml:"preset"`
	ResponseActions map[string]string `yaml:"response_actions"`
}

// defaultResponseActions defines the default action for each violation type.
var defaultResponseActions = map[string]string{
	"secret_exfil":           "warn",
	"ioc_match":              "block",
	"undeclared_destination": "warn",
	"undeclared_tool":        "block",
	"capability_violation":   "block",
	"dns_exfil":              "warn",
	"slow_drip":              "log",

	// Phase 12: MCP protection violation types.
	"pin_change_midsession": "block", // Mid-session rug-pull: always block (CONTEXT.md: no warn option)
	"pin_change_between":    "warn",  // Between-session change: warn + show diff
	"prompt_injection":      "warn",  // Injection detection: warn-only default (CONTEXT.md)
}

// validPresets enumerates the allowed preset names.
var validPresets = map[string]bool{
	"strict":     true,
	"moderate":   true,
	"permissive": true,
}

// validActions enumerates the allowed response action values.
var validActions = map[string]bool{
	"block": true,
	"warn":  true,
	"log":   true,
}

// DefaultPolicyConfig returns a PolicyConfig with moderate preset and default response actions.
func DefaultPolicyConfig() *PolicyConfig {
	actions := make(map[string]string, len(defaultResponseActions))
	for k, v := range defaultResponseActions {
		actions[k] = v
	}
	return &PolicyConfig{
		Preset:          "moderate",
		ResponseActions: actions,
	}
}

// LoadPolicyConfig parses YAML bytes into a PolicyConfig, validating all values.
func LoadPolicyConfig(data []byte) (*PolicyConfig, error) {
	var pc PolicyConfig
	if err := yaml.Unmarshal(data, &pc); err != nil {
		return nil, fmt.Errorf("parsing policy config YAML: %w", err)
	}

	// Validate preset
	if pc.Preset != "" && !validPresets[pc.Preset] {
		return nil, fmt.Errorf("invalid preset %q: must be one of strict, moderate, permissive", pc.Preset)
	}

	// Validate response actions
	for vType, action := range pc.ResponseActions {
		if !validActions[strings.ToLower(action)] {
			return nil, fmt.Errorf("invalid response action %q for violation type %q: must be one of block, warn, log", action, vType)
		}
	}

	return &pc, nil
}

// MergePolicyConfigs layers override on top of base. Override's preset replaces base's
// if non-empty. Override's response_actions overwrite individual keys (not full replacement).
func MergePolicyConfigs(base, override *PolicyConfig) *PolicyConfig {
	result := &PolicyConfig{
		Preset:          base.Preset,
		ResponseActions: make(map[string]string, len(base.ResponseActions)),
	}

	// Copy base actions
	for k, v := range base.ResponseActions {
		result.ResponseActions[k] = v
	}

	// Apply overrides
	if override.Preset != "" {
		result.Preset = override.Preset
	}
	for k, v := range override.ResponseActions {
		result.ResponseActions[k] = v
	}

	return result
}

// ActionFor returns the ActionType for a given violation type.
// Fail-closed: unknown violation types return ActionBlock.
func (pc *PolicyConfig) ActionFor(violationType string) ActionType {
	if action, ok := pc.ResponseActions[violationType]; ok {
		switch strings.ToLower(action) {
		case "block":
			return ActionBlock
		case "warn":
			return ActionWarn
		case "log":
			return ActionLog
		}
	}
	// Fail-closed: unknown violation types default to block
	return ActionBlock
}
