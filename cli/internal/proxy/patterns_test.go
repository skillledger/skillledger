package proxy_test

import (
	"testing"

	"github.com/skillledger/skillledger/internal/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadPatterns_Count(t *testing.T) {
	patterns := proxy.LoadPatterns()
	assert.GreaterOrEqual(t, len(patterns), 30, "should have at least 30 secret patterns")
}

func TestLoadPatterns_AllRegexCompile(t *testing.T) {
	patterns := proxy.LoadPatterns()
	for _, p := range patterns {
		assert.NotNilf(t, p.Regex, "pattern %s has nil Regex", p.Name)
	}
}

func TestLoadPatterns_PrefixNonEmpty(t *testing.T) {
	patterns := proxy.LoadPatterns()
	for _, p := range patterns {
		assert.NotEmptyf(t, p.Prefix, "pattern %s has empty Prefix", p.Name)
	}
}

func TestLoadPatterns_KnownSamples(t *testing.T) {
	patterns := proxy.LoadPatterns()

	tests := []struct {
		name     string
		sample   string
		wantName string
	}{
		{
			name:     "AWS access key ID",
			sample:   "AKIA1234567890ABCDEF",
			wantName: "aws-access-key-id",
		},
		{
			name:     "GitHub PAT",
			sample:   "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk",
			wantName: "github-pat",
		},
		{
			name:     "Stripe live secret key",
			sample:   "sk_live_1234567890abcdefghijklmn",
			wantName: "stripe-secret-key",
		},
		{
			name:     "Anthropic API key",
			sample:   "sk-ant-api03-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaAA",
			wantName: "anthropic-api-key",
		},
		{
			name:     "Slack bot token",
			sample:   "xoxb-123456789012-123456789012-abcdefghijklmnopqrstuvwx",
			wantName: "slack-bot-token",
		},
		{
			name:     "JWT token",
			sample:   "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456ghi",
			wantName: "jwt-token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched := false
			for _, p := range patterns {
				if p.Name == tt.wantName {
					require.True(t, p.Regex.MatchString(tt.sample),
						"pattern %s should match sample %q", p.Name, tt.sample)
					matched = true
					break
				}
			}
			require.True(t, matched, "pattern %s not found in LoadPatterns()", tt.wantName)
		})
	}
}

func TestLoadPatterns_NoFalsePositive(t *testing.T) {
	patterns := proxy.LoadPatterns()

	safeWords := []string{"skeleton", "skill", "sketch", "skip", "skull", "sky"}
	for _, word := range safeWords {
		for _, p := range patterns {
			assert.Falsef(t, p.Regex.MatchString(word),
				"pattern %s should NOT match common word %q", p.Name, word)
		}
	}
}

func TestHighestDecision(t *testing.T) {
	tests := []struct {
		name     string
		findings []proxy.Finding
		want     proxy.ActionType
	}{
		{
			name:     "empty findings returns allow",
			findings: nil,
			want:     proxy.ActionAllow,
		},
		{
			name: "single block",
			findings: []proxy.Finding{
				{Decision: proxy.ActionBlock},
			},
			want: proxy.ActionBlock,
		},
		{
			name: "block overrides warn",
			findings: []proxy.Finding{
				{Decision: proxy.ActionWarn},
				{Decision: proxy.ActionBlock},
				{Decision: proxy.ActionLog},
			},
			want: proxy.ActionBlock,
		},
		{
			name: "warn overrides log",
			findings: []proxy.Finding{
				{Decision: proxy.ActionLog},
				{Decision: proxy.ActionWarn},
				{Decision: proxy.ActionAllow},
			},
			want: proxy.ActionWarn,
		},
		{
			name: "log overrides allow",
			findings: []proxy.Finding{
				{Decision: proxy.ActionAllow},
				{Decision: proxy.ActionLog},
			},
			want: proxy.ActionLog,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := proxy.HighestDecision(tt.findings)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRedact(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", "****"},
		{"short", "****"},
		{"12345678", "****"},
		{"123456789", "1234****6789"},
		{"sk-ant-api03-verylongsecretkey", "sk-a****tkey"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := proxy.Redact(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestFormatFindings(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		assert.Equal(t, "no findings", proxy.FormatFindings(nil))
	})

	t.Run("multiple findings", func(t *testing.T) {
		findings := []proxy.Finding{
			{Severity: "critical", Scanner: "secret", Description: "AWS key found"},
			{Severity: "high", Scanner: "network", Description: "C2 domain detected"},
		}
		result := proxy.FormatFindings(findings)
		assert.Contains(t, result, "[critical] secret: AWS key found")
		assert.Contains(t, result, "[high] network: C2 domain detected")
	})
}
