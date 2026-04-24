package proxy

import "regexp"

// SecretPattern defines a regex-based secret detection pattern with metadata.
type SecretPattern struct {
	Name        string
	Provider    string
	Prefix      string
	Regex       *regexp.Regexp
	Description string
	Severity    string
}

// LoadPatterns returns the bundled set of secret detection patterns.
// Patterns are ordered so more specific prefixes come first (e.g., sk-ant- before sk-proj- before sk-).
// All regexes are compiled at load time via regexp.MustCompile.
func LoadPatterns() []SecretPattern {
	return []SecretPattern{
		// AWS
		{
			Name:        "aws-access-key-id",
			Provider:    "aws",
			Prefix:      "AKIA",
			Regex:       regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
			Description: "AWS access key ID",
			Severity:    "critical",
		},
		{
			Name:        "aws-secret-access-key",
			Provider:    "aws",
			Prefix:      "aws_secret",
			Regex:       regexp.MustCompile(`(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?`),
			Description: "AWS secret access key assignment",
			Severity:    "critical",
		},

		// GCP
		{
			Name:        "gcp-api-key",
			Provider:    "gcp",
			Prefix:      "AIza",
			Regex:       regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`),
			Description: "Google Cloud API key",
			Severity:    "critical",
		},
		{
			Name:        "gcp-service-account-key",
			Provider:    "gcp",
			Prefix:      "\"type\": \"service_account\"",
			Regex:       regexp.MustCompile(`"type"\s*:\s*"service_account"`),
			Description: "GCP service account JSON key",
			Severity:    "critical",
		},

		// GitHub (ordered most specific first)
		{
			Name:        "github-fine-grained-pat",
			Provider:    "github",
			Prefix:      "github_pat_",
			Regex:       regexp.MustCompile(`github_pat_[0-9a-zA-Z_]{22,}`),
			Description: "GitHub fine-grained personal access token",
			Severity:    "critical",
		},
		{
			Name:        "github-pat",
			Provider:    "github",
			Prefix:      "ghp_",
			Regex:       regexp.MustCompile(`ghp_[0-9a-zA-Z]{36,}`),
			Description: "GitHub personal access token",
			Severity:    "critical",
		},
		{
			Name:        "github-oauth",
			Provider:    "github",
			Prefix:      "gho_",
			Regex:       regexp.MustCompile(`gho_[0-9a-zA-Z]{36,}`),
			Description: "GitHub OAuth access token",
			Severity:    "critical",
		},
		{
			Name:        "github-app",
			Provider:    "github",
			Prefix:      "ghs_",
			Regex:       regexp.MustCompile(`ghs_[0-9a-zA-Z]{36,}`),
			Description: "GitHub App installation token",
			Severity:    "critical",
		},

		// Stripe (ordered most specific first)
		{
			Name:        "stripe-restricted-key",
			Provider:    "stripe",
			Prefix:      "rk_live_",
			Regex:       regexp.MustCompile(`rk_live_[0-9a-zA-Z]{24,}`),
			Description: "Stripe restricted API key",
			Severity:    "critical",
		},
		{
			Name:        "stripe-secret-key",
			Provider:    "stripe",
			Prefix:      "sk_live_",
			Regex:       regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`),
			Description: "Stripe live secret key",
			Severity:    "critical",
		},
		{
			Name:        "stripe-test-key",
			Provider:    "stripe",
			Prefix:      "sk_test_",
			Regex:       regexp.MustCompile(`sk_test_[0-9a-zA-Z]{24,}`),
			Description: "Stripe test secret key",
			Severity:    "medium",
		},

		// Anthropic (before generic sk-)
		{
			Name:        "anthropic-api-key",
			Provider:    "anthropic",
			Prefix:      "sk-ant-",
			Regex:       regexp.MustCompile(`sk-ant-[a-zA-Z0-9_-]{80,}AA`),
			Description: "Anthropic API key",
			Severity:    "critical",
		},

		// OpenAI (ordered most specific first)
		{
			Name:        "openai-project-key",
			Provider:    "openai",
			Prefix:      "sk-proj-",
			Regex:       regexp.MustCompile(`sk-proj-[a-zA-Z0-9_-]{48,}`),
			Description: "OpenAI project API key",
			Severity:    "critical",
		},
		{
			Name:        "openai-api-key",
			Provider:    "openai",
			Prefix:      "sk-",
			Regex:       regexp.MustCompile(`sk-[a-zA-Z0-9]{20,}`),
			Description: "OpenAI API key",
			Severity:    "critical",
		},

		// Slack
		{
			Name:        "slack-bot-token",
			Provider:    "slack",
			Prefix:      "xoxb-",
			Regex:       regexp.MustCompile(`xoxb-[0-9]+-[0-9]+-[a-zA-Z0-9]+`),
			Description: "Slack bot token",
			Severity:    "critical",
		},
		{
			Name:        "slack-user-token",
			Provider:    "slack",
			Prefix:      "xoxp-",
			Regex:       regexp.MustCompile(`xoxp-[0-9]+-[0-9]+-[0-9]+-[a-f0-9]+`),
			Description: "Slack user token",
			Severity:    "critical",
		},
		{
			Name:        "slack-app-token",
			Provider:    "slack",
			Prefix:      "xoxa-",
			Regex:       regexp.MustCompile(`xoxa-[0-9]+-[a-zA-Z0-9]+`),
			Description: "Slack app-level token",
			Severity:    "high",
		},

		// Azure
		{
			Name:        "azure-subscription-key",
			Provider:    "azure",
			Prefix:      "Ocp-Apim-Subscription-Key",
			Regex:       regexp.MustCompile(`(?i)Ocp-Apim-Subscription-Key\s*[=:]\s*['"]?([0-9a-f]{32})['"]?`),
			Description: "Azure subscription key",
			Severity:    "critical",
		},
		{
			Name:        "azure-sas-token",
			Provider:    "azure",
			Prefix:      "sig=",
			Regex:       regexp.MustCompile(`(?i)[?&]sig=[a-zA-Z0-9%/+=]{40,}`),
			Description: "Azure SAS token",
			Severity:    "high",
		},

		// Twilio
		{
			Name:        "twilio-account-sid",
			Provider:    "twilio",
			Prefix:      "AC",
			Regex:       regexp.MustCompile(`AC[0-9a-f]{32}`),
			Description: "Twilio account SID",
			Severity:    "high",
		},
		{
			Name:        "twilio-auth-token",
			Provider:    "twilio",
			Prefix:      "twilio",
			Regex:       regexp.MustCompile(`(?i)twilio[_\-]?auth[_\-]?token\s*[=:]\s*['"]?([0-9a-f]{32})['"]?`),
			Description: "Twilio auth token",
			Severity:    "critical",
		},

		// SendGrid
		{
			Name:        "sendgrid-api-key",
			Provider:    "sendgrid",
			Prefix:      "SG.",
			Regex:       regexp.MustCompile(`SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}`),
			Description: "SendGrid API key",
			Severity:    "critical",
		},

		// Mailgun
		{
			Name:        "mailgun-api-key",
			Provider:    "mailgun",
			Prefix:      "key-",
			Regex:       regexp.MustCompile(`key-[0-9a-zA-Z]{32}`),
			Description: "Mailgun API key",
			Severity:    "high",
		},

		// Heroku
		{
			Name:        "heroku-api-key",
			Provider:    "heroku",
			Prefix:      "heroku",
			Regex:       regexp.MustCompile(`(?i)heroku[_\-]?api[_\-]?key\s*[=:]\s*['"]?([0-9a-f-]{36})['"]?`),
			Description: "Heroku API key",
			Severity:    "high",
		},

		// npm
		{
			Name:        "npm-access-token",
			Provider:    "npm",
			Prefix:      "npm_",
			Regex:       regexp.MustCompile(`npm_[0-9a-zA-Z]{36}`),
			Description: "npm access token",
			Severity:    "high",
		},

		// PyPI
		{
			Name:        "pypi-api-token",
			Provider:    "pypi",
			Prefix:      "pypi-",
			Regex:       regexp.MustCompile(`pypi-[0-9a-zA-Z_-]{50,}`),
			Description: "PyPI API token",
			Severity:    "high",
		},

		// Docker Hub
		{
			Name:        "docker-hub-pat",
			Provider:    "docker",
			Prefix:      "dckr_pat_",
			Regex:       regexp.MustCompile(`dckr_pat_[0-9a-zA-Z_-]{20,}`),
			Description: "Docker Hub personal access token",
			Severity:    "high",
		},

		// Telegram
		{
			Name:        "telegram-bot-token",
			Provider:    "telegram",
			Prefix:      "bot",
			Regex:       regexp.MustCompile(`[0-9]{8,10}:[0-9A-Za-z_-]{35}`),
			Description: "Telegram bot token",
			Severity:    "high",
		},

		// Generic patterns
		{
			Name:        "jwt-token",
			Provider:    "generic",
			Prefix:      "eyJ",
			Regex:       regexp.MustCompile(`eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}`),
			Description: "JSON Web Token",
			Severity:    "high",
		},
		{
			Name:        "private-key-pem",
			Provider:    "generic",
			Prefix:      "-----BEGIN",
			Regex:       regexp.MustCompile(`-----BEGIN\s+(RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
			Description: "PEM-encoded private key",
			Severity:    "critical",
		},
		{
			Name:        "bearer-token-header",
			Provider:    "generic",
			Prefix:      "Bearer ",
			Regex:       regexp.MustCompile(`(?i)(?:authorization|token)\s*[=:]\s*['"]?Bearer\s+[a-zA-Z0-9_\-.~+/]+=*['"]?`),
			Description: "Bearer token in header or config",
			Severity:    "high",
		},
		{
			Name:        "generic-hex-secret-64",
			Provider:    "generic",
			Prefix:      "secret",
			Regex:       regexp.MustCompile(`(?i)(?:secret|password|api[_\-]?key|token)\s*[=:]\s*['"]?[0-9a-f]{64}['"]?`),
			Description: "64-char hex string assigned to secret variable",
			Severity:    "high",
		},
		{
			Name:        "generic-base64-secret",
			Provider:    "generic",
			Prefix:      "secret",
			Regex:       regexp.MustCompile(`(?i)(?:secret|password|api[_\-]?key|private[_\-]?key)\s*[=:]\s*['"]?[A-Za-z0-9+/]{40,}={0,3}['"]?`),
			Description: "Base64 string assigned to secret variable",
			Severity:    "medium",
		},
	}
}
