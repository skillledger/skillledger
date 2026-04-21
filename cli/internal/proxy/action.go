// Package proxy implements the SkillLedger runtime proxy for intercepting skill I/O.
package proxy

import (
	"fmt"

	"github.com/google/uuid"
)

// ActionType represents the kind of action the proxy takes on intercepted traffic.
type ActionType string

const (
	// ActionAllow permits the intercepted message to pass through.
	ActionAllow ActionType = "allow"
	// ActionBlock stops the intercepted message from reaching its destination.
	ActionBlock ActionType = "block"
	// ActionWarn permits the message but records a warning for review.
	ActionWarn ActionType = "warn"
	// ActionLog permits the message and records it for audit purposes.
	ActionLog ActionType = "log"
)

// NewActionID generates a human-readable action identifier using an 8-char UUID prefix.
func NewActionID() string {
	return fmt.Sprintf("act-%s", uuid.New().String()[:8])
}
