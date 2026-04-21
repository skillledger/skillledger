// Package runtime provides per-ecosystem interception adapters for the SkillLedger runtime proxy.
package runtime

import (
	"github.com/spf13/afero"
)

// InterceptCapability describes which I/O channels an adapter can intercept.
type InterceptCapability struct {
	HTTP  bool `json:"http"`
	Stdio bool `json:"stdio"`
	FS    bool `json:"fs"`
}

// ConfigureOpts holds configuration options for a runtime adapter.
type ConfigureOpts struct {
	ProxyAddr string `json:"proxy_addr"`
	CAPath    string `json:"ca_path"`
}

// RuntimeAdapter provides per-ecosystem interception for the runtime proxy.
type RuntimeAdapter interface {
	Kind() string
	Capabilities() InterceptCapability
	Configure(fs afero.Fs, opts ConfigureOpts) error
}
