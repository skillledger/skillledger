package schema

import (
	"encoding/json"
	"fmt"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const coreSchemaURI = "https://skillledger.dev/schemas/v0.1/core.schema.json"
const schemaBaseURI = "https://skillledger.dev/schemas/v0.1/"

// Validator validates JSON data against the SkillLedger core schema.
type Validator struct {
	compiled *jsonschema.Schema
}

// NewValidator creates a Validator with all embedded schemas loaded.
func NewValidator() (*Validator, error) {
	c := jsonschema.NewCompiler()

	// Load top-level schemas
	entries, err := SchemaFS.ReadDir("schemas")
	if err != nil {
		return nil, fmt.Errorf("reading embedded schemas: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := SchemaFS.ReadFile("schemas/" + e.Name())
		if err != nil {
			return nil, fmt.Errorf("reading schema %s: %w", e.Name(), err)
		}
		var doc any
		if err := json.Unmarshal(data, &doc); err != nil {
			return nil, fmt.Errorf("parsing schema %s: %w", e.Name(), err)
		}
		if err := c.AddResource(schemaBaseURI+e.Name(), doc); err != nil {
			return nil, fmt.Errorf("adding schema %s: %w", e.Name(), err)
		}
	}

	// Load profile schemas
	profileEntries, err := SchemaFS.ReadDir("schemas/profiles")
	if err != nil {
		return nil, fmt.Errorf("reading embedded profile schemas: %w", err)
	}
	for _, e := range profileEntries {
		if e.IsDir() {
			continue
		}
		data, err := SchemaFS.ReadFile("schemas/profiles/" + e.Name())
		if err != nil {
			return nil, fmt.Errorf("reading profile schema %s: %w", e.Name(), err)
		}
		var doc any
		if err := json.Unmarshal(data, &doc); err != nil {
			return nil, fmt.Errorf("parsing profile schema %s: %w", e.Name(), err)
		}
		if err := c.AddResource(schemaBaseURI+"profiles/"+e.Name(), doc); err != nil {
			return nil, fmt.Errorf("adding profile schema %s: %w", e.Name(), err)
		}
	}

	compiled, err := c.Compile(coreSchemaURI)
	if err != nil {
		return nil, fmt.Errorf("compiling core schema: %w", err)
	}

	return &Validator{compiled: compiled}, nil
}

// Validate checks JSON data against the core schema.
func (v *Validator) Validate(jsonData []byte) error {
	var inst any
	if err := json.Unmarshal(jsonData, &inst); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	return v.compiled.Validate(inst)
}
