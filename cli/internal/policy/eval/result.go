package eval

// PolicyResult holds the outcome of evaluating a skill against a policy.
type PolicyResult struct {
	Decision   string   `json:"decision"`            // "allow", "deny", "warn"
	Violations []string `json:"violations,omitempty"` // deny messages
	Warnings   []string `json:"warnings,omitempty"`   // warn messages
}
