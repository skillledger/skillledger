package manifest

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/skillledger/skillledger/internal/schema"
	"gopkg.in/yaml.v3"
)

// ValidationError represents a single schema validation failure.
type ValidationError struct {
	Path    string
	Message string
}

var (
	validator     *schema.Validator
	validatorOnce sync.Once
	validatorErr  error
)

func getValidator() (*schema.Validator, error) {
	validatorOnce.Do(func() {
		validator, validatorErr = schema.NewValidator()
	})
	return validator, validatorErr
}

// ParseAndValidate parses YAML, validates against JSON Schema, and returns the typed manifest.
func ParseAndValidate(yamlBytes []byte) (*Manifest, []ValidationError, error) {
	// Step 1: Parse YAML into generic map
	var raw map[string]interface{}
	if err := yaml.Unmarshal(yamlBytes, &raw); err != nil {
		return nil, nil, fmt.Errorf("YAML parse error: %w", err)
	}

	// Step 2: Convert to JSON for schema validation
	jsonBytes, err := json.Marshal(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("JSON marshal error: %w", err)
	}

	// Step 3: Validate against JSON Schema
	v, err := getValidator()
	if err != nil {
		return nil, nil, fmt.Errorf("schema validator init error: %w", err)
	}

	if err := v.Validate(jsonBytes); err != nil {
		validationErrors := extractValidationErrors(err)
		return nil, validationErrors, nil
	}

	// Step 4: Parse into typed struct
	var m Manifest
	if err := yaml.Unmarshal(yamlBytes, &m); err != nil {
		return nil, nil, fmt.Errorf("manifest parse error: %w", err)
	}

	return &m, nil, nil
}

func extractValidationErrors(err error) []ValidationError {
	var errors []ValidationError

	if ve, ok := err.(*jsonschema.ValidationError); ok {
		collectErrors(ve, &errors)
	} else {
		errors = append(errors, ValidationError{
			Path:    "/",
			Message: err.Error(),
		})
	}

	return errors
}

func collectErrors(ve *jsonschema.ValidationError, errors *[]ValidationError) {
	if len(ve.Causes) == 0 {
		path := "/" + strings.Join(ve.InstanceLocation, "/")
		msg := ve.Error()
		// Use the leaf error message, stripping the jsonschema: prefix
		if idx := strings.LastIndex(msg, ": "); idx >= 0 {
			msg = msg[idx+2:]
		}
		*errors = append(*errors, ValidationError{
			Path:    path,
			Message: msg,
		})
		return
	}
	for _, cause := range ve.Causes {
		collectErrors(cause, errors)
	}
}
