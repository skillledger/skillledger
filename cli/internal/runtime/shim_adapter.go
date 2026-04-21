package runtime

import (
	"os"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
)

// ShimAdapter configures OpenClaw plugins that use HTTP_PROXY injection.
// This is a bypassable interception mechanism -- see the protection matrix
// for limitations.
type ShimAdapter struct{}

// Kind returns the adapter kind identifier.
func (a *ShimAdapter) Kind() string {
	return "openclaw-shim"
}

// Capabilities returns the interception capabilities of this adapter.
func (a *ShimAdapter) Capabilities() InterceptCapability {
	return InterceptCapability{HTTP: true, Stdio: false, FS: false}
}

// Configure sets HTTP_PROXY to route OpenClaw plugin traffic through the proxy.
func (a *ShimAdapter) Configure(_ afero.Fs, opts ConfigureOpts) error {
	if err := os.Setenv("HTTP_PROXY", opts.ProxyAddr); err != nil {
		return err
	}
	log.Warn().
		Str("proxy_addr", opts.ProxyAddr).
		Msg("OpenClaw shim uses HTTP_PROXY injection (bypassable) -- see protection matrix for limitations")
	return nil
}
