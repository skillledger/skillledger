package preset

import (
	_ "embed"
	"fmt"
)

//go:embed rego/strict.rego
var strictRego string

//go:embed rego/moderate.rego
var moderateRego string

//go:embed rego/permissive.rego
var permissiveRego string

// Get returns the Rego source for a named preset policy.
func Get(name string) (string, error) {
	return "", fmt.Errorf("not implemented")
}

// List returns all available preset names in alphabetical order.
func List() []string {
	return nil
}
