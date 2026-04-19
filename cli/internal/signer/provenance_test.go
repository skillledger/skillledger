package signer

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestProvenanceInput() ProvenanceInput {
	return ProvenanceInput{
		ArtifactName:   "com.example.test-skill-1.0.0-abc123def456.skillledger.tar.gz",
		ArtifactDigest: "abc123def456789012345678901234567890123456789012345678901234abcd",
		Repository:     "https://github.com/example/test-skill",
		Ref:            "abc123def456",
		Directory:      ".",
		BuiltAt:        "2026-04-19T12:00:00Z",
		BuilderVersion: "0.1.0",
	}
}

func TestProvenance_ValidStatement(t *testing.T) {
	input := newTestProvenanceInput()
	stmt, err := CreateProvenance(input)
	require.NoError(t, err)
	assert.NotNil(t, stmt)
}

func TestProvenance_SubjectDigest(t *testing.T) {
	input := newTestProvenanceInput()
	stmt, err := CreateProvenance(input)
	require.NoError(t, err)

	require.Len(t, stmt.Subject, 1)
	digest, ok := stmt.Subject[0].Digest["sha256"]
	assert.True(t, ok, "subject should have sha256 digest")
	assert.Equal(t, input.ArtifactDigest, digest)
}

func TestProvenance_SubjectName(t *testing.T) {
	input := newTestProvenanceInput()
	stmt, err := CreateProvenance(input)
	require.NoError(t, err)

	require.Len(t, stmt.Subject, 1)
	assert.Equal(t, input.ArtifactName, stmt.Subject[0].Name)
}

func TestProvenance_PredicateType(t *testing.T) {
	input := newTestProvenanceInput()
	stmt, err := CreateProvenance(input)
	require.NoError(t, err)

	assert.Equal(t, "https://slsa.dev/provenance/v1", stmt.PredicateType)
}

func TestProvenance_StatementType(t *testing.T) {
	input := newTestProvenanceInput()
	stmt, err := CreateProvenance(input)
	require.NoError(t, err)

	assert.Equal(t, "https://in-toto.io/Statement/v1", stmt.Type)
}

func TestProvenance_BuilderID(t *testing.T) {
	input := newTestProvenanceInput()
	stmt, err := CreateProvenance(input)
	require.NoError(t, err)

	predicate := stmt.Predicate.AsMap()
	runDetails, ok := predicate["runDetails"].(map[string]interface{})
	require.True(t, ok, "runDetails should be a map")

	builder, ok := runDetails["builder"].(map[string]interface{})
	require.True(t, ok, "builder should be a map")

	assert.Equal(t, "https://skillledger.dev/SkillBuilder/v1", builder["id"])
}

func TestProvenance_BuildType(t *testing.T) {
	input := newTestProvenanceInput()
	stmt, err := CreateProvenance(input)
	require.NoError(t, err)

	predicate := stmt.Predicate.AsMap()
	buildDef, ok := predicate["buildDefinition"].(map[string]interface{})
	require.True(t, ok, "buildDefinition should be a map")

	assert.Equal(t, "https://skillledger.dev/SkillBuild/v1", buildDef["buildType"])
}

func TestProvenance_SourceRepository(t *testing.T) {
	input := newTestProvenanceInput()
	stmt, err := CreateProvenance(input)
	require.NoError(t, err)

	predicate := stmt.Predicate.AsMap()
	buildDef, ok := predicate["buildDefinition"].(map[string]interface{})
	require.True(t, ok, "buildDefinition should be a map")

	extParams, ok := buildDef["externalParameters"].(map[string]interface{})
	require.True(t, ok, "externalParameters should be a map")

	assert.Equal(t, input.Repository, extParams["repository"])
}

func TestProvenance_Serialization(t *testing.T) {
	input := newTestProvenanceInput()
	stmt, err := CreateProvenance(input)
	require.NoError(t, err)

	data, err := SerializeStatement(stmt)
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	// Verify it's valid JSON
	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &parsed))

	// Verify key fields are present in serialized output
	assert.Contains(t, string(data), "https://slsa.dev/provenance/v1")
	assert.Contains(t, string(data), "https://in-toto.io/Statement/v1")
}

func TestProvenance_EmptyDigest(t *testing.T) {
	input := newTestProvenanceInput()
	input.ArtifactDigest = ""

	stmt, err := CreateProvenance(input)
	assert.Error(t, err)
	assert.Nil(t, stmt)
	assert.Contains(t, err.Error(), "artifact digest must be exactly 64 hex chars")
}

func TestProvenance_ShortDigest(t *testing.T) {
	input := newTestProvenanceInput()
	input.ArtifactDigest = "abc123" // only 6 chars, need 64

	stmt, err := CreateProvenance(input)
	assert.Error(t, err)
	assert.Nil(t, stmt)
	assert.Contains(t, err.Error(), "artifact digest must be exactly 64 hex chars")
}

func TestProvenance_InvalidHexDigest(t *testing.T) {
	input := newTestProvenanceInput()
	// 64 chars but contains non-hex characters
	input.ArtifactDigest = "zzzz23def456789012345678901234567890123456789012345678901234abcd"

	stmt, err := CreateProvenance(input)
	assert.Error(t, err)
	assert.Nil(t, stmt)
	assert.Contains(t, err.Error(), "artifact digest is not valid hex")
}

func TestProvenance_EmptyArtifactName(t *testing.T) {
	input := newTestProvenanceInput()
	input.ArtifactName = ""
	_, err := CreateProvenance(input)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "artifact name is required")
}

func TestProvenance_EmptyRepository(t *testing.T) {
	input := newTestProvenanceInput()
	input.Repository = ""
	_, err := CreateProvenance(input)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "repository URL is required")
}

func TestProvenance_EmptyRef(t *testing.T) {
	input := newTestProvenanceInput()
	input.Ref = ""
	_, err := CreateProvenance(input)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "git ref is required")
}

func TestProvenance_EmptyBuiltAt(t *testing.T) {
	input := newTestProvenanceInput()
	input.BuiltAt = ""
	_, err := CreateProvenance(input)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "build timestamp is required")
}

func TestProvenance_InvocationID(t *testing.T) {
	input := newTestProvenanceInput()
	stmt, err := CreateProvenance(input)
	require.NoError(t, err)

	predicate := stmt.Predicate.AsMap()
	runDetails, ok := predicate["runDetails"].(map[string]interface{})
	require.True(t, ok)

	metadata, ok := runDetails["metadata"].(map[string]interface{})
	require.True(t, ok)

	// invocationId should be first 12 chars of artifact digest
	assert.Equal(t, input.ArtifactDigest[:12], metadata["invocationId"])
}

func TestProvenance_BuilderVersion(t *testing.T) {
	input := newTestProvenanceInput()
	stmt, err := CreateProvenance(input)
	require.NoError(t, err)

	predicate := stmt.Predicate.AsMap()
	runDetails, ok := predicate["runDetails"].(map[string]interface{})
	require.True(t, ok)

	builder, ok := runDetails["builder"].(map[string]interface{})
	require.True(t, ok)

	version, ok := builder["version"].(map[string]interface{})
	require.True(t, ok)

	assert.Equal(t, input.BuilderVersion, version["skillledger"])
}

func TestProvenance_ResolvedDependencies(t *testing.T) {
	input := newTestProvenanceInput()
	stmt, err := CreateProvenance(input)
	require.NoError(t, err)

	predicate := stmt.Predicate.AsMap()
	buildDef, ok := predicate["buildDefinition"].(map[string]interface{})
	require.True(t, ok)

	deps, ok := buildDef["resolvedDependencies"].([]interface{})
	require.True(t, ok)
	require.Len(t, deps, 1)

	dep, ok := deps[0].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, input.Repository, dep["uri"])

	digest, ok := dep["digest"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, input.Ref, digest["gitCommit"])
}
