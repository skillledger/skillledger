package eval

import (
	"context"
	"fmt"

	"github.com/open-policy-agent/opa/v1/rego"
)

// Evaluator holds a prepared OPA query for reuse.
type Evaluator struct {
	prepared rego.PreparedEvalQuery
}

// NewEvaluator compiles a Rego module and prepares it for evaluation.
func NewEvaluator(regoSource string) (*Evaluator, error) {
	return nil, fmt.Errorf("not implemented")
}

// NewEvaluatorWithData compiles a Rego module with additional data and modules.
func NewEvaluatorWithData(regoSource string, modules map[string]string, data map[string]any) (*Evaluator, error) {
	return nil, fmt.Errorf("not implemented")
}

// Evaluate runs the policy against a skill's capabilities and attestation.
func (e *Evaluator) Evaluate(ctx context.Context, input map[string]any) (*PolicyResult, error) {
	return nil, fmt.Errorf("not implemented")
}

// ensure rego import is used
var _ = rego.New
