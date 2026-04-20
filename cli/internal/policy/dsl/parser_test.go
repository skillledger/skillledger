package dsl_test

import (
	"testing"

	"github.com/skillledger/skillledger/internal/policy/dsl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const validPolicyYAML = `
version: 1
rules:
  filesystem:
    - deny: contains("write")
      message: "Skills must not have write access"
    - warn: contains("read:/etc")
      message: "Reading /etc is suspicious"
  network:
    - deny: any("outbound")
      except: ["outbound:*.anthropic.com", "outbound:*.openai.com"]
      message: "Only Anthropic and OpenAI endpoints allowed"
  secrets:
    - deny: any("vault")
      message: "Vault access not permitted"
  tools:
    - deny: any("execute")
      except: ["execute:python"]
      message: "Only Python execution allowed"
publishers:
  allowlist:
    - cert-identity: "https://github.com/myorg/*"
      issuer: "https://accounts.google.com"
`

func TestParse(t *testing.T) {
	t.Run("valid policy with all capability categories", func(t *testing.T) {
		p, err := dsl.Parse([]byte(validPolicyYAML))
		require.NoError(t, err)
		require.NotNil(t, p)

		assert.Equal(t, 1, p.Version)
		assert.Len(t, p.Rules, 4, "should have filesystem, network, secrets, tools")

		// filesystem rules
		fsRules := p.Rules["filesystem"]
		require.Len(t, fsRules, 2)
		assert.Equal(t, `contains("write")`, fsRules[0].Deny)
		assert.Equal(t, "Skills must not have write access", fsRules[0].Message)
		assert.Equal(t, `contains("read:/etc")`, fsRules[1].Warn)
		assert.Equal(t, "Reading /etc is suspicious", fsRules[1].Message)

		// network rules
		netRules := p.Rules["network"]
		require.Len(t, netRules, 1)
		assert.Equal(t, `any("outbound")`, netRules[0].Deny)
		assert.Equal(t, "Only Anthropic and OpenAI endpoints allowed", netRules[0].Message)

		// secrets rules
		secRules := p.Rules["secrets"]
		require.Len(t, secRules, 1)
		assert.Equal(t, `any("vault")`, secRules[0].Deny)

		// tools rules
		toolRules := p.Rules["tools"]
		require.Len(t, toolRules, 1)
		assert.Equal(t, `any("execute")`, toolRules[0].Deny)
	})

	t.Run("except list populates Rule.Except", func(t *testing.T) {
		p, err := dsl.Parse([]byte(validPolicyYAML))
		require.NoError(t, err)

		netRules := p.Rules["network"]
		require.Len(t, netRules, 1)
		assert.Equal(t, []string{"outbound:*.anthropic.com", "outbound:*.openai.com"}, netRules[0].Except)

		toolRules := p.Rules["tools"]
		require.Len(t, toolRules, 1)
		assert.Equal(t, []string{"execute:python"}, toolRules[0].Except)
	})

	t.Run("publishers allowlist populates CertIdentity and Issuer", func(t *testing.T) {
		p, err := dsl.Parse([]byte(validPolicyYAML))
		require.NoError(t, err)

		require.Len(t, p.Publishers.Allowlist, 1)
		assert.Equal(t, "https://github.com/myorg/*", p.Publishers.Allowlist[0].CertIdentity)
		assert.Equal(t, "https://accounts.google.com", p.Publishers.Allowlist[0].Issuer)
	})

	t.Run("empty YAML returns error", func(t *testing.T) {
		_, err := dsl.Parse([]byte(""))
		assert.Error(t, err)

		_, err = dsl.Parse(nil)
		assert.Error(t, err)
	})

	t.Run("unknown fields do not error", func(t *testing.T) {
		yaml := `
version: 1
rules:
  filesystem:
    - deny: contains("write")
      message: "no write"
future_field: "should be ignored"
`
		p, err := dsl.Parse([]byte(yaml))
		require.NoError(t, err)
		assert.Equal(t, 1, p.Version)
	})

	t.Run("version validation rejects version 0 and missing", func(t *testing.T) {
		v0 := `
version: 0
rules:
  filesystem:
    - deny: contains("write")
      message: "no write"
`
		_, err := dsl.Parse([]byte(v0))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported policy version")

		noVersion := `
rules:
  filesystem:
    - deny: contains("write")
      message: "no write"
`
		_, err = dsl.Parse([]byte(noVersion))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported policy version")
	})

	t.Run("both deny and warn set returns error", func(t *testing.T) {
		bothSet := `
version: 1
rules:
  filesystem:
    - deny: contains("write")
      warn: contains("read")
      message: "invalid"
`
		_, err := dsl.Parse([]byte(bothSet))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "exactly one of deny or warn")
	})

	t.Run("neither deny nor warn set returns error", func(t *testing.T) {
		neitherSet := `
version: 1
rules:
  filesystem:
    - message: "no operator"
`
		_, err := dsl.Parse([]byte(neitherSet))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "exactly one of deny or warn")
	})

	t.Run("no rules returns error", func(t *testing.T) {
		noRules := `
version: 1
rules: {}
`
		_, err := dsl.Parse([]byte(noRules))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "at least one rule")
	})
}
