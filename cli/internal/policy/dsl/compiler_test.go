package dsl_test

import (
	"context"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/skillledger/skillledger/internal/policy/dsl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustParse(t *testing.T, yaml string) *dsl.Policy {
	t.Helper()
	p, err := dsl.Parse([]byte(yaml))
	require.NoError(t, err)
	return p
}

func TestCompile(t *testing.T) {
	t.Run("contains operator produces correct Rego", func(t *testing.T) {
		p := mustParse(t, `
version: 1
rules:
  filesystem:
    - deny: contains("write")
      message: "Skills must not have write access"
`)
		out, err := dsl.Compile(p)
		require.NoError(t, err)
		assert.Contains(t, out, "some cap in input.capabilities.filesystem")
		assert.Contains(t, out, `contains(cap, "write")`)
	})

	t.Run("any operator produces startswith Rego", func(t *testing.T) {
		p := mustParse(t, `
version: 1
rules:
  network:
    - deny: any("outbound")
      message: "No outbound"
`)
		out, err := dsl.Compile(p)
		require.NoError(t, err)
		assert.Contains(t, out, "some cap in input.capabilities.network")
		assert.Contains(t, out, `startswith(cap, "outbound")`)
	})

	t.Run("except list produces not-in set", func(t *testing.T) {
		p := mustParse(t, `
version: 1
rules:
  network:
    - deny: any("outbound")
      except: ["outbound:*.anthropic.com", "outbound:*.openai.com"]
      message: "Only allowed endpoints"
`)
		out, err := dsl.Compile(p)
		require.NoError(t, err)
		assert.Contains(t, out, `not cap in {"outbound:*.anthropic.com", "outbound:*.openai.com"}`)
	})

	t.Run("warn rule produces warnings set", func(t *testing.T) {
		p := mustParse(t, `
version: 1
rules:
  filesystem:
    - warn: contains("read:/etc")
      message: "Reading /etc is suspicious"
`)
		out, err := dsl.Compile(p)
		require.NoError(t, err)
		assert.Contains(t, out, "warnings contains msg if {")
		assert.NotContains(t, out, "deny contains msg if {")
	})

	t.Run("output starts with correct package and import", func(t *testing.T) {
		p := mustParse(t, `
version: 1
rules:
  filesystem:
    - deny: contains("write")
      message: "no write"
`)
		out, err := dsl.Compile(p)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(out, "package skillledger.policy\n"))
		assert.Contains(t, out, "import rego.v1")
	})

	t.Run("includes decision precedence logic", func(t *testing.T) {
		p := mustParse(t, `
version: 1
rules:
  filesystem:
    - deny: contains("write")
      message: "no write"
    - warn: contains("read:/etc")
      message: "suspicious read"
`)
		out, err := dsl.Compile(p)
		require.NoError(t, err)
		assert.Contains(t, out, `decision := "deny" if count(deny) > 0`)
		assert.Contains(t, out, `count(deny) == 0`)
		assert.Contains(t, out, `count(warnings) > 0`)
	})

	t.Run("nil policy returns error", func(t *testing.T) {
		_, err := dsl.Compile(nil)
		assert.Error(t, err)
	})

	t.Run("compiled Rego is parseable by OPA", func(t *testing.T) {
		p := mustParse(t, validPolicyYAML)
		out, err := dsl.Compile(p)
		require.NoError(t, err)

		// Verify OPA can parse and prepare the compiled Rego
		r := rego.New(
			rego.Module("test.rego", out),
			rego.Query("data.skillledger.policy"),
		)
		_, err = r.PrepareForEval(context.Background())
		require.NoError(t, err, "compiled Rego must be parseable by OPA; output:\n%s", out)
	})

	t.Run("unknown operator returns CompileError", func(t *testing.T) {
		p := &dsl.Policy{
			Version: 1,
			Rules: map[string][]dsl.Rule{
				"filesystem": {
					{Deny: `unknown("foo")`, Message: "bad op"},
				},
			},
		}
		_, err := dsl.Compile(p)
		assert.Error(t, err)
		var ce *dsl.CompileError
		assert.ErrorAs(t, err, &ce)
	})
}

func TestCompileRuntime_BlockDestination(t *testing.T) {
	rules := &dsl.RuntimeRuleSet{
		Block: []string{`destination contains "*.internal.corp"`},
	}
	out, err := dsl.CompileRuntime(rules)
	require.NoError(t, err)
	assert.Contains(t, out, "package skillledger.runtime_policy")
	assert.Contains(t, out, "import rego.v1")
	assert.Contains(t, out, "deny contains msg if {")
	assert.Contains(t, out, "input.action.destination")
}

func TestCompileRuntime_BlockTool(t *testing.T) {
	rules := &dsl.RuntimeRuleSet{
		Block: []string{`tool any ["rm", "exec", "eval"]`},
	}
	out, err := dsl.CompileRuntime(rules)
	require.NoError(t, err)
	assert.Contains(t, out, "deny contains msg if {")
	assert.Contains(t, out, `input.action.tool in {"rm", "exec", "eval"}`)
}

func TestCompileRuntime_WarnDestination(t *testing.T) {
	rules := &dsl.RuntimeRuleSet{
		Warn: []string{`destination except ["api.openai.com", "api.anthropic.com"]`},
	}
	out, err := dsl.CompileRuntime(rules)
	require.NoError(t, err)
	assert.Contains(t, out, "warnings contains msg if {")
	assert.Contains(t, out, `not input.action.destination in {"api.openai.com", "api.anthropic.com"}`)
}

func TestCompileRuntime_LogEntry(t *testing.T) {
	rules := &dsl.RuntimeRuleSet{
		Log: []string{`method contains "DELETE"`},
	}
	out, err := dsl.CompileRuntime(rules)
	require.NoError(t, err)
	assert.Contains(t, out, "log_entries contains msg if {")
	assert.Contains(t, out, `contains(input.action.method, "DELETE")`)
}

func TestCompileRuntime_MultipleRules(t *testing.T) {
	rules := &dsl.RuntimeRuleSet{
		Block: []string{
			`destination contains "*.evil.com"`,
			`tool any ["rm", "exec"]`,
		},
		Warn: []string{
			`method contains "DELETE"`,
		},
	}
	out, err := dsl.CompileRuntime(rules)
	require.NoError(t, err)
	assert.Equal(t, 2, strings.Count(out, "deny contains msg if {"))
	assert.Equal(t, 1, strings.Count(out, "warnings contains msg if {"))
}

func TestCompileRuntime_NilRules(t *testing.T) {
	out, err := dsl.CompileRuntime(nil)
	require.NoError(t, err)
	assert.Equal(t, "", out)
}

func TestCompileRuntime_InvalidField(t *testing.T) {
	rules := &dsl.RuntimeRuleSet{
		Block: []string{`invalid_field contains "foo"`},
	}
	_, err := dsl.CompileRuntime(rules)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported field")
}

func TestCompileRuntime_InjectionPrevention(t *testing.T) {
	rules := &dsl.RuntimeRuleSet{
		Block: []string{"destination contains \"foo\nbar\""},
	}
	_, err := dsl.CompileRuntime(rules)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "disallowed characters")
}

func TestCompileRuntime_CompilesValidRego(t *testing.T) {
	rules := &dsl.RuntimeRuleSet{
		Block: []string{`destination contains "*.evil.com"`},
		Warn:  []string{`tool any ["rm", "exec"]`},
		Log:   []string{`method contains "DELETE"`},
	}
	out, err := dsl.CompileRuntime(rules)
	require.NoError(t, err)

	r := rego.New(
		rego.Module("test.rego", out),
		rego.Query("data.skillledger.runtime_policy"),
	)
	_, err = r.PrepareForEval(context.Background())
	require.NoError(t, err, "compiled runtime Rego must be parseable by OPA; output:\n%s", out)
}

func TestCompileRuntime_EvaluatesCorrectly(t *testing.T) {
	rules := &dsl.RuntimeRuleSet{
		Block: []string{`destination contains "*.evil.com"`},
	}
	out, err := dsl.CompileRuntime(rules)
	require.NoError(t, err)

	r := rego.New(
		rego.Module("test.rego", out),
		rego.Query("data.skillledger.runtime_policy.deny"),
	)
	pq, err := r.PrepareForEval(context.Background())
	require.NoError(t, err)

	// Should match: data.evil.com matches *.evil.com glob
	rs, err := pq.Eval(context.Background(), rego.EvalInput(map[string]interface{}{
		"action": map[string]interface{}{
			"destination": "data.evil.com",
		},
	}))
	require.NoError(t, err)
	require.NotEmpty(t, rs)
	require.NotEmpty(t, rs[0].Expressions)
	// deny set should be non-empty
	denySet, ok := rs[0].Expressions[0].Value.([]interface{})
	if ok {
		assert.NotEmpty(t, denySet, "deny set should be non-empty for evil.com destination")
	}

	// Should NOT match: api.openai.com does not match *.evil.com
	rs, err = pq.Eval(context.Background(), rego.EvalInput(map[string]interface{}{
		"action": map[string]interface{}{
			"destination": "api.openai.com",
		},
	}))
	require.NoError(t, err)
	require.NotEmpty(t, rs)
	require.NotEmpty(t, rs[0].Expressions)
	denySet2, ok := rs[0].Expressions[0].Value.([]interface{})
	if ok {
		assert.Empty(t, denySet2, "deny set should be empty for openai.com destination")
	}
}

func TestParse_WithRuntimeRules(t *testing.T) {
	yamlData := `
version: 1
rules:
  filesystem:
    - deny: contains("write")
      message: "no write"
runtime-rules:
  block:
    - 'destination contains "*.evil.com"'
  warn:
    - 'tool any ["rm", "exec"]'
  log:
    - 'method contains "DELETE"'
`
	p, err := dsl.Parse([]byte(yamlData))
	require.NoError(t, err)
	require.NotNil(t, p.RuntimeRules)
	assert.Len(t, p.RuntimeRules.Block, 1)
	assert.Len(t, p.RuntimeRules.Warn, 1)
	assert.Len(t, p.RuntimeRules.Log, 1)
	assert.Equal(t, `destination contains "*.evil.com"`, p.RuntimeRules.Block[0])
}

func TestParse_RuntimeRulesEmptyExpression(t *testing.T) {
	yamlData := `
version: 1
rules:
  filesystem:
    - deny: contains("write")
      message: "no write"
runtime-rules:
  block:
    - ""
`
	_, err := dsl.Parse([]byte(yamlData))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "runtime-rules.block[0]: empty expression")
}
