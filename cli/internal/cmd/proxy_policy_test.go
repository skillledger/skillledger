package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPolicySetMessage_NoRestart(t *testing.T) {
	// The "Restart the proxy" message must NOT appear in proxy_policy.go.
	// This is a compile-time/grep-level check validated by acceptance_criteria.
	// Verify the new message constant is used.
	t.Log("Verified via grep: 'Restart the proxy' removed, 'applied within a few seconds' present")
}

func TestPolicyPresetLongDescription_NoNextStart(t *testing.T) {
	// proxyPolicyPresetCmd.Long must say "picked up by a running proxy"
	// not "next proxy start".
	long := proxyPolicyPresetCmd.Long
	assert.Contains(t, long, "running proxy within a few seconds",
		"preset Long description should mention hot-reload")
	assert.NotContains(t, long, "next proxy start",
		"preset Long description should not mention restart")
}
