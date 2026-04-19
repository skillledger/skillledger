package signer

import (
	"fmt"

	intoto "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

// ProvenanceInput contains the data needed to generate a SLSA provenance attestation.
type ProvenanceInput struct {
	ArtifactName   string // e.g., "com.example.skill-1.0.0-abc123def456.skillledger.tar.gz"
	ArtifactDigest string // hex-encoded SHA-256 of the artifact
	Repository     string // source repository URL
	Ref            string // git ref (commit SHA, tag, branch)
	Directory      string // subdirectory within repo (empty string if root)
	BuiltAt        string // RFC3339 timestamp from lockfile
	BuilderVersion string // SkillLedger version string, e.g. "0.1.0"
}

// CreateProvenance produces an in-toto Statement v1 with a SLSA Provenance v1
// predicate from the given build metadata. The returned statement is ready to
// be serialized (via SerializeStatement) and wrapped in a DSSE envelope for
// signing.
func CreateProvenance(input ProvenanceInput) (*intoto.Statement, error) {
	if len(input.ArtifactDigest) < 12 {
		return nil, fmt.Errorf("artifact digest too short: need at least 12 hex chars, got %d", len(input.ArtifactDigest))
	}

	subject := &intoto.ResourceDescriptor{
		Name:   input.ArtifactName,
		Digest: map[string]string{"sha256": input.ArtifactDigest},
	}

	predicate, err := structpb.NewStruct(map[string]interface{}{
		"buildDefinition": map[string]interface{}{
			"buildType": "https://skillledger.dev/SkillBuild/v1",
			"externalParameters": map[string]interface{}{
				"repository": input.Repository,
				"ref":        input.Ref,
				"directory":  input.Directory,
			},
			"resolvedDependencies": []interface{}{
				map[string]interface{}{
					"uri": input.Repository,
					"digest": map[string]interface{}{
						"gitCommit": input.Ref,
					},
				},
			},
		},
		"runDetails": map[string]interface{}{
			"builder": map[string]interface{}{
				"id": "https://skillledger.dev/SkillBuilder/v1",
				"version": map[string]interface{}{
					"skillledger": input.BuilderVersion,
				},
			},
			"metadata": map[string]interface{}{
				"invocationId": input.ArtifactDigest[:12],
				"startedOn":    input.BuiltAt,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("creating provenance predicate: %w", err)
	}

	stmt := &intoto.Statement{
		Type:          "https://in-toto.io/Statement/v1",
		Subject:       []*intoto.ResourceDescriptor{subject},
		PredicateType: "https://slsa.dev/provenance/v1",
		Predicate:     predicate,
	}

	if err := stmt.Validate(); err != nil {
		return nil, fmt.Errorf("validating in-toto statement: %w", err)
	}

	return stmt, nil
}

// SerializeStatement marshals an in-toto Statement to JSON using protojson
// (NOT encoding/json) for interoperability with external SLSA verifiers.
func SerializeStatement(stmt *intoto.Statement) ([]byte, error) {
	data, err := protojson.Marshal(stmt)
	if err != nil {
		return nil, fmt.Errorf("serializing statement: %w", err)
	}
	return data, nil
}
