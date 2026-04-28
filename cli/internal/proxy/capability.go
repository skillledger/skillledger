package proxy

import (
	"context"
	"fmt"
	"sync"

	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/skillledger/skillledger/internal/manifest"
	"github.com/skillledger/skillledger/internal/policy/preset"
)

// RuntimeAction describes a single action intercepted from a skill at runtime.
type RuntimeAction struct {
	SkillID     string `json:"skill_id"`
	ActionType  string `json:"action_type"` // "http_request", "mcp_tool_call", "mcp_resource_access"
	Destination string `json:"destination,omitempty"` // host:port for HTTP
	Method      string `json:"method,omitempty"`      // HTTP method or MCP method
	ToolName    string `json:"tool,omitempty"`         // MCP tool name
	Resource    string `json:"resource,omitempty"`     // MCP resource URI
	TrustTier   string `json:"trust_tier,omitempty"`   // "verified", "partial", "unverified" (Phase 13)
}

// ActionObserver is notified of runtime actions for learning/profiling purposes.
// Plan 02 implements this as the Profiler.
type ActionObserver interface {
	Observe(action RuntimeAction)
}

// RuntimeEvaluator evaluates skill actions against capability policy using OPA.
type RuntimeEvaluator struct {
	prepared  rego.PreparedEvalQuery
	manifests map[string]*manifest.Manifest
	config    *PolicyConfig
	observer  ActionObserver
	mu        sync.RWMutex
}

// NewRuntimeEvaluator creates a RuntimeEvaluator with the given preset and manifests.
func NewRuntimeEvaluator(presetName string, manifests map[string]*manifest.Manifest, config *PolicyConfig, observer ActionObserver, extraModules map[string]string) (*RuntimeEvaluator, error) {
	regoSource, err := preset.GetRuntime(presetName)
	if err != nil {
		return nil, fmt.Errorf("loading runtime preset %q: %w", presetName, err)
	}

	prepared, err := compileRuntimePolicy(regoSource, extraModules)
	if err != nil {
		return nil, err
	}

	if manifests == nil {
		manifests = make(map[string]*manifest.Manifest)
	}

	return &RuntimeEvaluator{
		prepared:  prepared,
		manifests: manifests,
		config:    config,
		observer:  observer,
	}, nil
}

// compileRuntimePolicy compiles Rego source into a PreparedEvalQuery targeting
// data.skillledger.runtime_policy (not data.skillledger.policy).
func compileRuntimePolicy(regoSource string, extraModules map[string]string) (rego.PreparedEvalQuery, error) {
	ctx := context.Background()
	opts := []func(*rego.Rego){
		rego.Query("data.skillledger.runtime_policy"),
		rego.Module("runtime_policy.rego", regoSource),
	}
	for name, src := range extraModules {
		opts = append(opts, rego.Module(name, src))
	}
	prepared, err := rego.New(opts...).PrepareForEval(ctx)
	if err != nil {
		return rego.PreparedEvalQuery{}, fmt.Errorf("compiling runtime policy: %w", err)
	}
	return prepared, nil
}

// Evaluate checks a RuntimeAction against the skill's declared capabilities.
// Returns findings with allow/block/warn decisions. Fail-closed on errors.
func (re *RuntimeEvaluator) Evaluate(ctx context.Context, action RuntimeAction) []Finding {
	re.mu.RLock()
	prepared := re.prepared
	re.mu.RUnlock()

	m, ok := re.manifests[action.SkillID]
	if !ok {
		// Learning mode: no manifest for this skill, observe and allow
		if re.observer != nil {
			re.observer.Observe(action)
		}
		return nil
	}

	// Notify observer if present
	if re.observer != nil {
		re.observer.Observe(action)
	}

	input := buildRuntimeInput(action, m)

	rs, err := prepared.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		// Fail-closed: OPA error produces block finding
		return []Finding{{
			Scanner:     "capability",
			Severity:    "critical",
			Description: "policy evaluation error: " + err.Error(),
			Decision:    ActionBlock,
		}}
	}

	return re.parseRuntimeResult(rs)
}

// buildRuntimeInput constructs the OPA input map from a RuntimeAction and Manifest.
func buildRuntimeInput(action RuntimeAction, m *manifest.Manifest) map[string]any {
	// Ensure nil slices become empty slices for OPA
	network := m.Capabilities.Network
	if network == nil {
		network = []string{}
	}
	tools := m.Capabilities.Tools
	if tools == nil {
		tools = []string{}
	}
	filesystem := m.Capabilities.Filesystem
	if filesystem == nil {
		filesystem = []string{}
	}
	secrets := m.Capabilities.Secrets
	if secrets == nil {
		secrets = []string{}
	}

	// Default trust_tier to "verified" when absent for backward compatibility
	// (pre-Phase 13 callers don't set TrustTier)
	trustTier := action.TrustTier
	if trustTier == "" {
		trustTier = "verified"
	}

	return map[string]any{
		"action": map[string]any{
			"type":        action.ActionType,
			"destination": action.Destination,
			"method":      action.Method,
			"tool":        action.ToolName,
			"resource":    action.Resource,
		},
		"manifest": map[string]any{
			"capabilities": map[string]any{
				"network":    toAnySlice(network),
				"tools":      toAnySlice(tools),
				"filesystem": toAnySlice(filesystem),
				"secrets":    toAnySlice(secrets),
			},
		},
		"trust_tier": trustTier,
	}
}

// toAnySlice converts []string to []any for OPA input compatibility.
func toAnySlice(ss []string) []any {
	result := make([]any, len(ss))
	for i, s := range ss {
		result[i] = s
	}
	return result
}

// parseRuntimeResult converts an OPA ResultSet into proxy Findings.
// Fail-closed: empty results produce ActionBlock.
func (re *RuntimeEvaluator) parseRuntimeResult(rs rego.ResultSet) []Finding {
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return []Finding{{
			Scanner:     "capability",
			Severity:    "high",
			Description: "policy denied action (empty result)",
			Decision:    re.config.ActionFor("capability_violation"),
		}}
	}

	val, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return []Finding{{
			Scanner:     "capability",
			Severity:    "high",
			Description: "policy denied action (invalid result type)",
			Decision:    re.config.ActionFor("capability_violation"),
		}}
	}

	var findings []Finding

	// Extract deny messages
	denyMsgs := extractStringSetFromResult(val, "deny")
	for _, msg := range denyMsgs {
		findings = append(findings, Finding{
			Scanner:     "capability",
			Severity:    "high",
			Description: msg,
			Decision:    re.config.ActionFor("capability_violation"),
		})
	}

	// Extract warning messages
	warnMsgs := extractStringSetFromResult(val, "warnings")
	for _, msg := range warnMsgs {
		findings = append(findings, Finding{
			Scanner:     "capability",
			Severity:    "medium",
			Description: msg,
			Decision:    ActionWarn,
		})
	}

	// Fail-closed: if decision is "deny" but no explicit messages
	if decision, ok := val["decision"].(string); ok && decision == "deny" && len(denyMsgs) == 0 {
		findings = append(findings, Finding{
			Scanner:     "capability",
			Severity:    "high",
			Description: "policy denied action",
			Decision:    re.config.ActionFor("capability_violation"),
		})
	}

	return findings
}

// extractStringSetFromResult pulls a set or slice of strings from OPA result map.
func extractStringSetFromResult(val map[string]any, key string) []string {
	raw, ok := val[key]
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case []any:
		strs := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				strs = append(strs, s)
			}
		}
		return strs
	case map[string]any:
		// OPA sets are represented as maps with true values
		strs := make([]string, 0, len(v))
		for k := range v {
			strs = append(strs, k)
		}
		return strs
	default:
		return nil
	}
}

// ReloadPolicy hot-swaps the OPA policy without blocking ongoing evaluations.
// Compiles the new policy outside the lock to minimize contention.
func (re *RuntimeEvaluator) ReloadPolicy(presetName string, extraModules map[string]string) error {
	regoSource, err := preset.GetRuntime(presetName)
	if err != nil {
		return fmt.Errorf("loading runtime preset %q: %w", presetName, err)
	}

	// Compile outside the lock (per Pitfall 1)
	prepared, err := compileRuntimePolicy(regoSource, extraModules)
	if err != nil {
		return err
	}

	re.mu.Lock()
	re.prepared = prepared
	re.mu.Unlock()

	return nil
}

// AddManifest registers or updates a skill manifest (thread-safe).
func (re *RuntimeEvaluator) AddManifest(skillID string, m *manifest.Manifest) {
	re.mu.Lock()
	re.manifests[skillID] = m
	re.mu.Unlock()
}

// Manifests returns a copy of the current manifest map.
func (re *RuntimeEvaluator) Manifests() map[string]*manifest.Manifest {
	re.mu.RLock()
	defer re.mu.RUnlock()
	copy := make(map[string]*manifest.Manifest, len(re.manifests))
	for k, v := range re.manifests {
		copy[k] = v
	}
	return copy
}
