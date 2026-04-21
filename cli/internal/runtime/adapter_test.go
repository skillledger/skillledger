package runtime_test

import (
	"testing"

	"github.com/skillledger/skillledger/internal/runtime"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Compile-time interface checks.
var (
	_ runtime.RuntimeAdapter = &runtime.HTTPProxyAdapter{}
	_ runtime.RuntimeAdapter = &runtime.MCPStdioAdapter{}
	_ runtime.RuntimeAdapter = &runtime.ShimAdapter{}
)

func TestRuntimeAdapterInterface(t *testing.T) {
	adapters := []runtime.RuntimeAdapter{
		&runtime.HTTPProxyAdapter{},
		&runtime.MCPStdioAdapter{},
		&runtime.ShimAdapter{},
	}
	for _, a := range adapters {
		assert.NotEmpty(t, a.Kind())
		_ = a.Capabilities()
	}
}

func TestRuntimeRegistry_DefaultRegistry(t *testing.T) {
	reg := runtime.DefaultRuntimeRegistry()
	all := reg.All()
	require.Len(t, all, 3)
}

func TestRuntimeRegistry_ForKind(t *testing.T) {
	reg := runtime.DefaultRuntimeRegistry()

	a, ok := reg.ForKind("http-proxy")
	require.True(t, ok)
	assert.Equal(t, "http-proxy", a.Kind())

	_, ok = reg.ForKind("nonexistent")
	assert.False(t, ok)
}

func TestHTTPAdapter_Capabilities(t *testing.T) {
	a := &runtime.HTTPProxyAdapter{}
	caps := a.Capabilities()
	assert.True(t, caps.HTTP)
	assert.False(t, caps.Stdio)
	assert.False(t, caps.FS)
}

func TestMCPStdioAdapter_Capabilities(t *testing.T) {
	a := &runtime.MCPStdioAdapter{}
	caps := a.Capabilities()
	assert.False(t, caps.HTTP)
	assert.True(t, caps.Stdio)
	assert.False(t, caps.FS)
}

func TestShimAdapter_Capabilities(t *testing.T) {
	a := &runtime.ShimAdapter{}
	caps := a.Capabilities()
	assert.True(t, caps.HTTP)
	assert.False(t, caps.Stdio)
	assert.False(t, caps.FS)
}

func TestHTTPAdapter_Configure(t *testing.T) {
	a := &runtime.HTTPProxyAdapter{}
	fs := afero.NewMemMapFs()
	err := a.Configure(fs, runtime.ConfigureOpts{ProxyAddr: "http://127.0.0.1:8080"})
	require.NoError(t, err)
}

func TestMCPStdioAdapter_Configure(t *testing.T) {
	a := &runtime.MCPStdioAdapter{}
	fs := afero.NewMemMapFs()
	err := a.Configure(fs, runtime.ConfigureOpts{})
	require.NoError(t, err)
}

func TestShimAdapter_Configure(t *testing.T) {
	a := &runtime.ShimAdapter{}
	fs := afero.NewMemMapFs()
	err := a.Configure(fs, runtime.ConfigureOpts{ProxyAddr: "http://127.0.0.1:8080"})
	require.NoError(t, err)
}
