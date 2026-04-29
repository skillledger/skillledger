package proxy

import (
	"net/http"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"github.com/skillledger/skillledger/internal/yara"
)

// YARAScanner wraps the v1 yara.Engine to implement the proxy Scanner interface.
// It scans HTTP request/response bodies against user-supplied YARA rules.
type YARAScanner struct {
	engine *yara.Engine
}

// NewYARAScanner creates a YARAScanner from rules in the given directory.
// Returns nil if rulesDir is empty, does not exist, contains no valid rules,
// or if compilation fails. This allows the proxy to run without YARA rules.
//
// CR-06b: The fs parameter is used for the directory existence check. However,
// the underlying yara.Engine (yargo) requires real filesystem paths for its C-based
// rule parser, so rule file reads still go through the real OS. This is an accepted
// exception documented here.
func NewYARAScanner(fs afero.Fs, rulesDir string) *YARAScanner {
	if rulesDir == "" {
		return nil
	}

	if _, err := fs.Stat(rulesDir); err != nil {
		return nil
	}

	// yara.NewEngine reads rule files via the real filesystem (yargo/C library requirement).
	engine, err := yara.NewEngine(rulesDir)
	if err != nil {
		log.Warn().Err(err).Str("dir", rulesDir).Msg("YARA rules compilation failed, scanner disabled")
		return nil
	}

	return &YARAScanner{engine: engine}
}

// Scan runs compiled YARA rules against the request body and returns findings.
// Each YARA match produces a Finding with scanner="yara" and severity from rule meta.
func (y *YARAScanner) Scan(_ *http.Request, body []byte) []Finding {
	if len(body) == 0 {
		return nil
	}

	matches, err := y.engine.Scan(body)
	if err != nil {
		log.Warn().Err(err).Msg("YARA runtime scan failed")
		return nil
	}

	var findings []Finding
	for _, m := range matches {
		findings = append(findings, Finding{
			Scanner:     "yara",
			Severity:    severityOrDefault(m.Severity, "medium"),
			Description: m.RuleName,
			Decision:    ActionWarn,
		})
	}
	return findings
}

// severityOrDefault returns sev if non-empty, otherwise returns def.
func severityOrDefault(sev, def string) string {
	if sev != "" {
		return sev
	}
	return def
}
