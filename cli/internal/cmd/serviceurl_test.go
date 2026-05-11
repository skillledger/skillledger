package cmd

import (
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestResolveServiceURL_Default(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("service-url", defaultServiceURL, "test")
	assert.Equal(t, "https://api.skillledger.in", resolveServiceURL(cmd, "service-url"))
}

func TestResolveServiceURL_EnvOverride(t *testing.T) {
	os.Setenv("SKILLLEDGER_SERVICE_URL", "http://localhost:9999")
	defer os.Unsetenv("SKILLLEDGER_SERVICE_URL")

	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("service-url", defaultServiceURL, "test")
	assert.Equal(t, "http://localhost:9999", resolveServiceURL(cmd, "service-url"))
}

func TestResolveServiceURL_FlagExplicit(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("service-url", defaultServiceURL, "test")
	cmd.Flags().Set("service-url", "http://custom:8080")
	assert.Equal(t, "http://custom:8080", resolveServiceURL(cmd, "service-url"))
}

func TestResolveServiceURL_FlagOverridesEnv(t *testing.T) {
	os.Setenv("SKILLLEDGER_SERVICE_URL", "http://env-url:1234")
	defer os.Unsetenv("SKILLLEDGER_SERVICE_URL")

	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("service-url", defaultServiceURL, "test")
	cmd.Flags().Set("service-url", "http://flag-url:5678")
	assert.Equal(t, "http://flag-url:5678", resolveServiceURL(cmd, "service-url"))
}
