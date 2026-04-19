package sbom_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/skillledger/skillledger/internal/ecosystem"
	"github.com/skillledger/skillledger/internal/sbom"
	"github.com/skillledger/skillledger/internal/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeScanResult(name, version, kind, sha256 string) scanner.ScanResult {
	return scanner.ScanResult{
		Skill: ecosystem.DiscoveredSkill{
			ID:      name,
			Name:    name,
			Version: version,
			Kind:    kind,
		},
		SHA256: sha256,
		Status: "clean",
	}
}

func TestGenerateCycloneDX_ValidJSON(t *testing.T) {
	results := []scanner.ScanResult{
		makeScanResult("skill-a", "1.0.0", "mcp-server", "aaa111"),
		makeScanResult("skill-b", "2.0.0", "claude-skill", "bbb222"),
	}

	var buf bytes.Buffer
	err := sbom.GenerateCycloneDX(&buf, results)
	require.NoError(t, err)

	var raw json.RawMessage
	err = json.Unmarshal(buf.Bytes(), &raw)
	assert.NoError(t, err, "output should be valid JSON")
}

func TestGenerateCycloneDX_ComponentCount(t *testing.T) {
	results := []scanner.ScanResult{
		makeScanResult("s1", "1.0", "", "h1"),
		makeScanResult("s2", "2.0", "", "h2"),
		makeScanResult("s3", "3.0", "", "h3"),
	}

	var buf bytes.Buffer
	err := sbom.GenerateCycloneDX(&buf, results)
	require.NoError(t, err)

	bom := new(cdx.BOM)
	decoder := cdx.NewBOMDecoder(bytes.NewReader(buf.Bytes()), cdx.BOMFileFormatJSON)
	err = decoder.Decode(bom)
	require.NoError(t, err)
	require.NotNil(t, bom.Components)
	assert.Equal(t, 3, len(*bom.Components))
}

func TestGenerateCycloneDX_SkillMetadata(t *testing.T) {
	results := []scanner.ScanResult{
		makeScanResult("test-skill", "1.0.0", "mcp-server", "abc123"),
	}

	var buf bytes.Buffer
	err := sbom.GenerateCycloneDX(&buf, results)
	require.NoError(t, err)

	bom := new(cdx.BOM)
	decoder := cdx.NewBOMDecoder(bytes.NewReader(buf.Bytes()), cdx.BOMFileFormatJSON)
	err = decoder.Decode(bom)
	require.NoError(t, err)
	require.NotNil(t, bom.Components)
	require.Equal(t, 1, len(*bom.Components))

	comp := (*bom.Components)[0]
	assert.Equal(t, "mcp-server", comp.Group)
	assert.Equal(t, "test-skill", comp.Name)
	assert.Equal(t, "1.0.0", comp.Version)
	require.NotNil(t, comp.Hashes)
	require.Equal(t, 1, len(*comp.Hashes))
	assert.Equal(t, cdx.HashAlgoSHA256, (*comp.Hashes)[0].Algorithm)
	assert.Equal(t, "abc123", (*comp.Hashes)[0].Value)
}

func TestGenerateCycloneDX_EmptyResults(t *testing.T) {
	var buf bytes.Buffer
	err := sbom.GenerateCycloneDX(&buf, []scanner.ScanResult{})
	require.NoError(t, err)

	var raw json.RawMessage
	err = json.Unmarshal(buf.Bytes(), &raw)
	assert.NoError(t, err, "output should be valid JSON even with empty results")
}

func TestGenerateCycloneDX_SerialNumber(t *testing.T) {
	results := []scanner.ScanResult{
		makeScanResult("s1", "1.0", "", "h1"),
	}

	var buf bytes.Buffer
	err := sbom.GenerateCycloneDX(&buf, results)
	require.NoError(t, err)

	bom := new(cdx.BOM)
	decoder := cdx.NewBOMDecoder(bytes.NewReader(buf.Bytes()), cdx.BOMFileFormatJSON)
	err = decoder.Decode(bom)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(bom.SerialNumber, "urn:uuid:"), "serial number should start with urn:uuid:")
}
