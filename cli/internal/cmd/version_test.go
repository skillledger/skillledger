package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVersionVariableIsNotEmpty(t *testing.T) {
	// The version variable should have a non-empty default value
	assert.NotEmpty(t, version, "version variable should not be empty")
}

func TestVersionVariableDefaultIsDev(t *testing.T) {
	// Without ldflags override, version should default to "dev"
	assert.Equal(t, "dev", version, "version default should be 'dev'")
}

func TestRootCmdVersionIsSet(t *testing.T) {
	// rootCmd.Version should be set by version.go's init() function
	assert.NotEmpty(t, rootCmd.Version, "rootCmd.Version should be set after init()")
}
