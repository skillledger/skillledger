package proxy_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/skillledger/skillledger/internal/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolicyHotReload(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	baseDir := t.TempDir()
	proxyDir := filepath.Join(baseDir, "proxy")
	require.NoError(t, os.MkdirAll(proxyDir, 0750))

	// Write initial policy config.
	initialConfig := []byte("preset: moderate\n")
	configPath := filepath.Join(proxyDir, "policy.yaml")
	require.NoError(t, os.WriteFile(configPath, initialConfig, 0640))

	// Create server with the base dir (policyFilePath auto-set to {baseDir}/proxy/policy.yaml).
	server := proxy.NewProxyServer(
		proxy.WithPort(0),
		proxy.WithBaseDir(baseDir),
		proxy.WithLogger(zerolog.Nop()),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- server.Start(ctx) }()

	// Wait for server to start and watcher to initialize.
	time.Sleep(300 * time.Millisecond)

	// Verify initial preset.
	assert.Equal(t, "moderate", server.PolicyConfig().Preset)

	// Write updated policy config.
	updatedConfig := []byte("preset: strict\n")
	require.NoError(t, os.WriteFile(configPath, updatedConfig, 0640))

	// Wait for fsnotify + 200ms debounce + reload.
	time.Sleep(600 * time.Millisecond)

	// Verify preset was hot-reloaded.
	assert.Equal(t, "strict", server.PolicyConfig().Preset,
		"PolicyConfig should be hot-reloaded after policy.yaml change")

	// Shutdown.
	cancel()
	select {
	case err := <-errCh:
		assert.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("server did not shut down in time")
	}
}

func TestPolicyHotReload_InvalidYAML_KeepsOldConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	baseDir := t.TempDir()
	proxyDir := filepath.Join(baseDir, "proxy")
	require.NoError(t, os.MkdirAll(proxyDir, 0750))

	initialConfig := []byte("preset: moderate\n")
	configPath := filepath.Join(proxyDir, "policy.yaml")
	require.NoError(t, os.WriteFile(configPath, initialConfig, 0640))

	server := proxy.NewProxyServer(
		proxy.WithPort(0),
		proxy.WithBaseDir(baseDir),
		proxy.WithLogger(zerolog.Nop()),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- server.Start(ctx) }()
	time.Sleep(300 * time.Millisecond)

	// Write invalid YAML.
	require.NoError(t, os.WriteFile(configPath, []byte("preset: [invalid yaml"), 0640))
	time.Sleep(600 * time.Millisecond)

	// Config should remain unchanged (Pitfall 4: keep old config on parse failure).
	assert.Equal(t, "moderate", server.PolicyConfig().Preset,
		"PolicyConfig should be unchanged after invalid YAML write")

	cancel()
	select {
	case err := <-errCh:
		assert.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("server did not shut down in time")
	}
}
