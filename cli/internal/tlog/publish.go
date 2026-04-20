package tlog

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

var sha256Pattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// PublishInput contains the validated inputs for publishing an artifact
// entry to the transparency log.
type PublishInput struct {
	ArtifactID     string
	SHA256         string
	ContentAddress string
	Publisher      string
	ServiceURL     string
}

// PublishResult holds the outcome of a successful publish operation.
type PublishResult struct {
	LogIndex   int64
	ArtifactID string
}

// Publish validates the input and submits an artifact entry to the
// transparency log service. It returns the log index assigned to the entry.
func Publish(ctx context.Context, input PublishInput) (*PublishResult, error) {
	// T-05-16: Validate all fields before making network call
	if input.ArtifactID == "" {
		return nil, fmt.Errorf("artifact ID is required")
	}
	if !sha256Pattern.MatchString(input.SHA256) {
		return nil, fmt.Errorf("SHA256 must be 64 lowercase hex characters")
	}
	if !strings.HasPrefix(input.ContentAddress, "sha256-") {
		return nil, fmt.Errorf("content address must start with \"sha256-\"")
	}
	if input.Publisher == "" {
		return nil, fmt.Errorf("publisher identity is required")
	}

	serviceURL := input.ServiceURL
	if serviceURL == "" {
		serviceURL = "http://localhost:8000"
	}

	client := NewClient(WithServiceURL(serviceURL))
	resp, err := client.PublishEntry(ctx, &PublishRequest{
		ArtifactID:     input.ArtifactID,
		SHA256:         input.SHA256,
		ContentAddress: input.ContentAddress,
		Publisher:      input.Publisher,
	})
	if err != nil {
		return nil, fmt.Errorf("publishing to transparency log: %w", err)
	}

	return &PublishResult{
		LogIndex:   resp.LogIndex,
		ArtifactID: resp.ArtifactID,
	}, nil
}
