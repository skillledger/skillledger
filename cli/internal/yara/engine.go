package yara

import (
	"encoding/json"
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

// YaraRuleItem represents a single YARA rule from the /v1/yara JSON response.
type YaraRuleItem struct {
	Name    string `json:"name"`
	Content string `json:"content"`
	Source  string `json:"source"`
}

// yaraRulesResponse is the JSON shape of the cached yara.json file.
type yaraRulesResponse struct {
	Rules []YaraRuleItem `json:"rules"`
}

// NewEngineFromRules creates an Engine from pre-parsed YARA rule items
// (typically loaded from the sync cache). It concatenates all Content fields,
// then parses and compiles using the same path as NewEngine.
func NewEngineFromRules(rules []YaraRuleItem) (*Engine, error) {
	if len(rules) == 0 {
		return nil, fmt.Errorf("no YARA rules provided")
	}

	var ruleContent strings.Builder
	for _, r := range rules {
		ruleContent.WriteString(r.Content)
		ruleContent.WriteByte('\n')
	}

	p := parser.New()
	ruleSet, err := p.Parse(ruleContent.String())
	if err != nil {
		return nil, fmt.Errorf("parsing YARA rules: %w", err)
	}

	compiled, err := yargoScanner.Compile(ruleSet)
	if err != nil {
		return nil, fmt.Errorf("compiling YARA rules: %w", err)
	}

	return &Engine{rules: compiled}, nil
}

// LoadCachedRules reads yara.json from cacheDir, parses the JSON
// (shape: {"rules": [...]}), and returns the rules slice.
// Returns error if file is missing or JSON is invalid.
func LoadCachedRules(cacheDir string) ([]YaraRuleItem, error) {
	data, err := os.ReadFile(filepath.Join(cacheDir, "yara.json"))
	if err != nil {
		return nil, fmt.Errorf("reading cached YARA rules: %w", err)
	}

	var resp yaraRulesResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parsing cached YARA rules: %w", err)
	}

	return resp.Rules, nil
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

		// Extract severity from meta "severity" field if present.
		if sevVal := m.MetaString("severity", ""); sevVal != "" {
			info.Severity = sevVal
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
