package yara

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sansecio/yargo/parser"
	yargoScanner "github.com/sansecio/yargo/scanner"
	"github.com/skillledger/skillledger/internal/scanner"
)

// Match represents a single YARA rule match.
type Match struct {
	RuleName string   `json:"rule_name"`
	Tags     []string `json:"tags,omitempty"`
}

// Engine compiles and executes YARA rules.
type Engine struct {
	rules *yargoScanner.Rules
}

// defaultScanTimeout is the per-scan timeout for YARA rule evaluation.
const defaultScanTimeout = 30 * time.Second

// NewEngine compiles all .yar and .yara files in rulesDir.
// Returns error if no rule files are found or if any rule fails to compile.
func NewEngine(rulesDir string) (*Engine, error) {
	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		return nil, fmt.Errorf("reading YARA rules directory: %w", err)
	}

	var ruleContent strings.Builder
	found := 0

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		ext := filepath.Ext(name)
		if ext != ".yar" && ext != ".yara" {
			continue
		}

		fullPath := filepath.Join(rulesDir, name)

		// Security: validate resolved path stays within rules directory (WR-04)
		resolved, err := filepath.EvalSymlinks(fullPath)
		if err != nil {
			return nil, fmt.Errorf("resolving rule file path %s: %w", name, err)
		}
		resolvedDir, err := filepath.EvalSymlinks(rulesDir)
		if err != nil {
			return nil, fmt.Errorf("resolving rules directory: %w", err)
		}
		if !strings.HasPrefix(resolved, resolvedDir+string(os.PathSeparator)) {
			return nil, fmt.Errorf("rule file %s escapes rules directory", name)
		}

		data, err := os.ReadFile(fullPath)
		if err != nil {
			return nil, fmt.Errorf("reading rule file %s: %w", name, err)
		}

		ruleContent.Write(data)
		ruleContent.WriteByte('\n')
		found++
	}

	if found == 0 {
		return nil, fmt.Errorf("no .yar or .yara files found in %s", rulesDir)
	}

	// Parse all rules
	p := parser.New()
	ruleSet, err := p.Parse(ruleContent.String())
	if err != nil {
		return nil, fmt.Errorf("parsing YARA rules: %w", err)
	}

	// Compile rules
	compiled, err := yargoScanner.Compile(ruleSet)
	if err != nil {
		return nil, fmt.Errorf("compiling YARA rules: %w", err)
	}

	return &Engine{rules: compiled}, nil
}

// Scan runs compiled YARA rules against content bytes.
// Returns matches as []scanner.YARAMatchInfo to satisfy the scanner.YARAScanner interface.
func (e *Engine) Scan(content []byte) ([]scanner.YARAMatchInfo, error) {
	if e.rules == nil {
		return nil, nil
	}

	var matches yargoScanner.MatchRules
	if err := e.rules.ScanMem(content, 0, defaultScanTimeout, &matches); err != nil {
		return nil, fmt.Errorf("YARA scan failed: %w", err)
	}

	if len(matches) == 0 {
		return nil, nil
	}

	results := make([]scanner.YARAMatchInfo, 0, len(matches))
	for _, m := range matches {
		info := scanner.YARAMatchInfo{
			RuleName: m.Rule,
		}

		// Extract tags from meta "tags" field if present (comma-separated).
		// yargo v0.2.0 does not expose YARA tags directly in the AST,
		// so we use a meta convention instead.
		if tagsVal := m.MetaString("tags", ""); tagsVal != "" {
			parts := strings.Split(tagsVal, ",")
			tags := make([]string, 0, len(parts))
			for _, t := range parts {
				t = strings.TrimSpace(t)
				if t != "" {
					tags = append(tags, t)
				}
			}
			if len(tags) > 0 {
				info.Tags = tags
			}
		}

		results = append(results, info)
	}
	return results, nil
}
