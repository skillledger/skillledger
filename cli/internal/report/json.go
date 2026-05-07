package report

import (
	"encoding/json"
	"io"

	"github.com/skillledger/skillledger/internal/scanner"
)

// GenerateJSON writes scan results as a pretty-printed JSON array to w.
func GenerateJSON(w io.Writer, results []scanner.ScanResult) error {
	if results == nil {
		results = []scanner.ScanResult{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(results)
}
