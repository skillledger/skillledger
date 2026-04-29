package proxy

import (
	"fmt"
	"os"

	"github.com/spf13/afero"
	"gopkg.in/yaml.v3"
)

// AllowlistEntry represents a single entry in the injection allowlist file.
type AllowlistEntry struct {
	ServerID string `yaml:"server_id"`
	ToolName string `yaml:"tool_name"`
	Reason   string `yaml:"reason"`
}

// allowlistFile is the YAML structure of the injection allowlist file.
type allowlistFile struct {
	Entries []AllowlistEntry `yaml:"entries"`
}

// InjectionAllowlist suppresses prompt injection findings for known false
// positive server+tool combinations. Entries are keyed by "serverID::toolName".
type InjectionAllowlist struct {
	entries map[string]bool
}

// LoadInjectionAllowlist reads an injection allowlist from a YAML file via afero.Fs (CR-06a).
// If the file does not exist, it returns an empty allowlist (not an error).
// The YAML file should have the structure:
//
//	entries:
//	  - server_id: "my-server"
//	    tool_name: "my-tool"
//	    reason: "known false positive"
func LoadInjectionAllowlist(fs afero.Fs, path string) (*InjectionAllowlist, error) {
	al := &InjectionAllowlist{
		entries: make(map[string]bool),
	}

	data, err := afero.ReadFile(fs, path)
	if err != nil {
		if os.IsNotExist(err) {
			// Missing file is not an error -- return empty allowlist.
			return al, nil
		}
		return nil, fmt.Errorf("read injection allowlist: %w", err)
	}

	var f allowlistFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse injection allowlist: %w", err)
	}

	for _, e := range f.Entries {
		key := e.ServerID + "::" + e.ToolName
		al.entries[key] = true
	}

	return al, nil
}

// IsAllowed returns true if the given server+tool combination is in the allowlist.
func (a *InjectionAllowlist) IsAllowed(serverID, toolName string) bool {
	if a == nil {
		return false
	}
	key := serverID + "::" + toolName
	return a.entries[key]
}
