package proxy

import "regexp"

// InjectionPattern defines a heuristic pattern for prompt injection detection.
// Each pattern has a short prefix for Aho-Corasick first-pass matching and a
// regex for second-pass confirmation, mirroring the SecretScanner two-pass approach.
type InjectionPattern struct {
	Name       string         // unique pattern identifier (e.g., "ignore-previous")
	Category   string         // category grouping (e.g., "instruction_override")
	Prefix     string         // short string for Aho-Corasick first pass
	Regex      *regexp.Regexp // confirmation regex for second pass
	Severity   string         // "high", "medium", "low"
	Confidence float64        // heuristic confidence score [0.0, 1.0]
}

// LoadInjectionPatterns returns the bundled set of prompt injection detection patterns.
// Patterns cover 5 categories per CONTEXT.md: instruction_override, system_prompt_leak,
// delimiter_injection, role_impersonation, and encoded_payload (handled at scan time).
// All regexes are compiled at load time via regexp.MustCompile.
func LoadInjectionPatterns() []InjectionPattern {
	return []InjectionPattern{
		// --- Instruction Override ---
		{
			Name:       "ignore-previous",
			Category:   "instruction_override",
			Prefix:     "ignore",
			Regex:      regexp.MustCompile(`(?i)ignore\s+(all\s+)?previous\s+(instructions?|prompts?|rules?|context)`),
			Severity:   "high",
			Confidence: 0.95,
		},
		{
			Name:       "disregard-previous",
			Category:   "instruction_override",
			Prefix:     "disregard",
			Regex:      regexp.MustCompile(`(?i)disregard\s+(all\s+)?previous\s+(instructions?|prompts?|rules?)`),
			Severity:   "high",
			Confidence: 0.95,
		},
		{
			Name:       "forget-everything",
			Category:   "instruction_override",
			Prefix:     "forget",
			Regex:      regexp.MustCompile(`(?i)forget\s+(everything|all)\s+(you\s+)?(know|learned|were\s+told)`),
			Severity:   "high",
			Confidence: 0.90,
		},
		{
			Name:       "new-instructions",
			Category:   "instruction_override",
			Prefix:     "new instruct",
			Regex:      regexp.MustCompile(`(?i)(new|updated?|revised?)\s+(system\s+)?(instructions?|prompt|rules?)\s*:`),
			Severity:   "high",
			Confidence: 0.85,
		},
		{
			Name:       "system-override",
			Category:   "instruction_override",
			Prefix:     "override",
			Regex:      regexp.MustCompile(`(?i)(system\s+)?override\s+(system\s+)?(settings?|rules?|restrictions?|guardrails?)`),
			Severity:   "high",
			Confidence: 0.85,
		},

		// --- System Prompt Leak ---
		{
			Name:       "show-system-prompt",
			Category:   "system_prompt_leak",
			Prefix:     "system prompt",
			Regex:      regexp.MustCompile(`(?i)(show|reveal|display|output|repeat|print)\s+(me\s+)?(the\s+)?(system\s+prompt|instructions?|full\s+prompt)`),
			Severity:   "high",
			Confidence: 0.90,
		},
		{
			Name:       "verbatim-instructions",
			Category:   "system_prompt_leak",
			Prefix:     "verbatim",
			Regex:      regexp.MustCompile(`(?i)repeat\s+(the\s+)?(instructions?|prompt)\s+verbatim`),
			Severity:   "high",
			Confidence: 0.90,
		},

		// --- Delimiter Injection ---
		{
			Name:       "triple-backtick-injection",
			Category:   "delimiter_injection",
			Prefix:     "```",
			Regex:      regexp.MustCompile("(?s)```[\\s\\S]*?(system|assistant|user)\\s*:"),
			Severity:   "medium",
			Confidence: 0.70,
		},
		{
			Name:       "im-sep-injection",
			Category:   "delimiter_injection",
			Prefix:     "<|im_sep|>",
			Regex:      regexp.MustCompile(`<\|im_(sep|start|end)\|>`),
			Severity:   "high",
			Confidence: 0.95,
		},
		{
			Name:       "xml-tag-injection",
			Category:   "delimiter_injection",
			Prefix:     "<system>",
			Regex:      regexp.MustCompile(`(?i)<(system|assistant|user|IMPORTANT)>`),
			Severity:   "medium",
			Confidence: 0.75,
		},

		// --- Role Impersonation ---
		{
			Name:       "role-impersonation",
			Category:   "role_impersonation",
			Prefix:     "Assistant:",
			Regex:      regexp.MustCompile(`(?mi)^(Assistant|System|Human|User)\s*:`),
			Severity:   "medium",
			Confidence: 0.65,
		},
		{
			Name:       "developer-mode",
			Category:   "role_impersonation",
			Prefix:     "developer mode",
			Regex:      regexp.MustCompile(`(?i)you\s+are\s+now\s+in\s+developer\s+mode`),
			Severity:   "high",
			Confidence: 0.90,
		},
	}
}
