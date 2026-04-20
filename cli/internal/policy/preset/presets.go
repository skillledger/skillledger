package preset

import (
	_ "embed"
	"fmt"
	"sort"
)

//go:embed rego/strict.rego
var strictRego string

//go:embed rego/moderate.rego
var moderateRego string

//go:embed rego/permissive.rego
var permissiveRego string

var presets = map[string]string{
	"strict":     strictRego,
	"moderate":   moderateRego,
	"permissive": permissiveRego,
}

// Get returns the Rego source for a named preset policy.
func Get(name string) (string, error) {
	src, ok := presets[name]
	if !ok {
		return "", fmt.Errorf("unknown preset %q: available: strict, moderate, permissive", name)
	}
	return src, nil
}

// List returns all available preset names in alphabetical order.
func List() []string {
	names := make([]string, 0, len(presets))
	for name := range presets {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
