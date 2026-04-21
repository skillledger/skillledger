package runtime

import (
	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
)

// MCPStdioAdapter handles MCP servers that communicate via stdio JSON-RPC.
// Stdio wrapping is handled by the proxy's fork-exec mechanism, not env vars.
type MCPStdioAdapter struct{}

// Kind returns the adapter kind identifier.
func (a *MCPStdioAdapter) Kind() string {
	return "mcp-stdio"
}

// Capabilities returns the interception capabilities of this adapter.
func (a *MCPStdioAdapter) Capabilities() InterceptCapability {
	return InterceptCapability{HTTP: false, Stdio: true, FS: false}
}

// Configure is a no-op for MCP stdio. Stdio wrapping is configured separately
// by the proxy's fork-exec mechanism.
func (a *MCPStdioAdapter) Configure(_ afero.Fs, _ ConfigureOpts) error {
	log.Debug().Msg("MCP stdio wrapping is configured separately by fork-exec")
	return nil
}
