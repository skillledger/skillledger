package report

import (
	"encoding/json"
	"io"

	"github.com/skillledger/skillledger/internal/scanner"
)

// GenerateJSON writes scan results as a pretty-printed JSON array to w.
func GenerateJSON(w io.Writer, results []scanner.ScanResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(results)
}
