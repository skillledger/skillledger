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
