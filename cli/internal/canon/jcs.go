package canon

import (
	"fmt"

	jcs "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

// Canonicalize produces RFC 8785 (JCS) canonical JSON from input JSON data.
func Canonicalize(jsonData []byte) ([]byte, error) {
	result, err := jcs.Transform(jsonData)
	if err != nil {
		return nil, fmt.Errorf("JCS canonicalization failed: %w", err)
	}
	return result, nil
}
