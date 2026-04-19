package sbom

import (
	"crypto/rand"
	"fmt"
	"io"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/skillledger/skillledger/internal/scanner"
)

// generateUUID creates a UUID v4 string without an external dependency.
func generateUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// GenerateCycloneDX writes a CycloneDX 1.6 JSON BOM to w from scan results.
func GenerateCycloneDX(w io.Writer, results []scanner.ScanResult) error {
	bom := cdx.NewBOM()
	bom.SerialNumber = "urn:uuid:" + generateUUID()
	bom.Metadata = &cdx.Metadata{
		Component: &cdx.Component{
			Type: cdx.ComponentTypeApplication,
			Name: "skillledger-audit",
		},
	}

	components := make([]cdx.Component, 0, len(results))
	for _, r := range results {
		comp := cdx.Component{
			Type:    cdx.ComponentTypeLibrary,
			Name:    r.Skill.Name,
			Version: r.Skill.Version,
			Hashes: &[]cdx.Hash{
				{Algorithm: cdx.HashAlgoSHA256, Value: r.SHA256},
			},
		}
		if r.Skill.Kind != "" {
			comp.Group = r.Skill.Kind
		}
		components = append(components, comp)
	}
	bom.Components = &components

	encoder := cdx.NewBOMEncoder(w, cdx.BOMFileFormatJSON)
	encoder.SetPretty(true)
	return encoder.Encode(bom)
}
