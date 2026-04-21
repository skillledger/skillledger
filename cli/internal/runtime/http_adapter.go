package runtime

import (
	"os"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
)

// HTTPProxyAdapter configures ecosystems that use HTTP_PROXY/HTTPS_PROXY
// environment variables to route traffic through the SkillLedger proxy.
// Covers Claude Code, OpenAI, Codex, Anthropic, OpenCode (6 ecosystems via HTTP).
type HTTPProxyAdapter struct{}

// Kind returns the adapter kind identifier.
func (a *HTTPProxyAdapter) Kind() string {
	return "http-proxy"
}

// Capabilities returns the interception capabilities of this adapter.
func (a *HTTPProxyAdapter) Capabilities() InterceptCapability {
	return InterceptCapability{HTTP: true, Stdio: false, FS: false}
}

// Configure sets HTTP_PROXY and HTTPS_PROXY environment variables to route
// traffic through the SkillLedger proxy.
func (a *HTTPProxyAdapter) Configure(_ afero.Fs, opts ConfigureOpts) error {
	if err := os.Setenv("HTTP_PROXY", opts.ProxyAddr); err != nil {
		return err
	}
	if err := os.Setenv("HTTPS_PROXY", opts.ProxyAddr); err != nil {
		return err
	}
	log.Debug().
		Str("proxy_addr", opts.ProxyAddr).
		Msg("configured HTTP_PROXY and HTTPS_PROXY for HTTP interception")
	return nil
}
