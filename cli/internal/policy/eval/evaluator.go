package eval

import (
	"context"
	"fmt"
	"sort"

	"github.com/open-policy-agent/opa/v1/rego"
)

// Evaluator holds a prepared OPA query for reuse.
type Evaluator struct {
	prepared rego.PreparedEvalQuery
}

// NewEvaluator compiles a Rego module and prepares it for evaluation.
func NewEvaluator(regoSource string) (*Evaluator, error) {
	ctx := context.Background()
	query, err := rego.New(
		rego.Query("data.skillledger.policy"),
		rego.Module("policy.rego", regoSource),
	).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("preparing policy query: %w", err)
	}
	return &Evaluator{prepared: query}, nil
}

// NewEvaluatorWithData compiles a Rego module with additional modules and data for evaluation.
func NewEvaluatorWithData(regoSource string, modules map[string]string, data map[string]any) (*Evaluator, error) {
	ctx := context.Background()
	opts := []func(*rego.Rego){
		rego.Query("data.skillledger.policy"),
		rego.Module("policy.rego", regoSource),
	}
	for name, src := range modules {
		opts = append(opts, rego.Module(name, src))
	}
	if data != nil {
		opts = append(opts, rego.Data(data))
	}
	query, err := rego.New(opts...).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("preparing policy query with data: %w", err)
	}
	return &Evaluator{prepared: query}, nil
}

// Evaluate runs the policy against a skill's capabilities and attestation.
func (e *Evaluator) Evaluate(ctx context.Context, input map[string]any) (*PolicyResult, error) {
	rs, err := e.prepared.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, fmt.Errorf("evaluating policy: %w", err)
	}
	return parseResult(rs)
}

// parseResult converts an OPA ResultSet into a PolicyResult.
// Fail-closed: empty result set returns deny.
func parseResult(rs rego.ResultSet) (*PolicyResult, error) {
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return &PolicyResult{Decision: "deny"}, nil
	}

	val, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return &PolicyResult{Decision: "deny"}, nil
	}

	result := &PolicyResult{Decision: "deny"}

	if d, ok := val["decision"].(string); ok {
		result.Decision = d
	}

	result.Violations = extractStringSet(val, "deny")
	result.Warnings = extractStringSet(val, "warnings")

	return result, nil
}

// extractStringSet pulls a set or slice of strings from the OPA result map.
func extractStringSet(val map[string]any, key string) []string {
	raw, ok := val[key]
	if !ok {
		return nil
	}

	switch v := raw.(type) {
	case []any:
		return anySliceToStrings(v)
	case map[string]any:
		// OPA sets are represented as maps with true values.
		// Sort for deterministic output across runs.
		strs := make([]string, 0, len(v))
		for k := range v {
			strs = append(strs, k)
		}
		sort.Strings(strs)
		return strs
	default:
		return nil
	}
}

func anySliceToStrings(s []any) []string {
	strs := make([]string, 0, len(s))
	for _, item := range s {
		if str, ok := item.(string); ok {
			strs = append(strs, str)
		}
	}
	return strs
}
