package dsl

import (
	"fmt"
	"sort"
	"strings"
)

// CompileError represents an error in compiling a specific rule.
type CompileError struct {
	Category string
	Index    int
	Message  string
}

func (e *CompileError) Error() string {
	return fmt.Sprintf("rule %s[%d]: %s", e.Category, e.Index, e.Message)
}

// Compile transforms a Policy AST into valid Rego source code.
// The output uses package skillledger.policy and import rego.v1.
func Compile(p *Policy) (string, error) {
	if p == nil {
		return "", fmt.Errorf("policy is nil")
	}
	if len(p.Rules) == 0 {
		return "", fmt.Errorf("policy has no rules")
	}

	var b strings.Builder

	// Header
	b.WriteString("package skillledger.policy\n\n")
	b.WriteString("import rego.v1\n\n")
	b.WriteString("default decision := \"allow\"\n\n")

	// Sort categories for deterministic output
	categories := make([]string, 0, len(p.Rules))
	for cat := range p.Rules {
		categories = append(categories, cat)
	}
	sort.Strings(categories)

	for _, category := range categories {
		rules := p.Rules[category]
		for i, rule := range rules {
			if err := compileRule(&b, category, i, rule); err != nil {
				return "", err
			}
		}
	}

	// Decision precedence logic
	b.WriteString("decision := \"deny\" if count(deny) > 0\n\n")
	b.WriteString("decision := \"warn\" if {\n")
	b.WriteString("    count(deny) == 0\n")
	b.WriteString("    count(warnings) > 0\n")
	b.WriteString("}\n")

	return b.String(), nil
}

func compileRule(b *strings.Builder, category string, index int, rule Rule) error {
	expr := rule.Deny
	ruleSet := "deny"
	if rule.Warn != "" {
		expr = rule.Warn
		ruleSet = "warnings"
	}

	op, arg, err := parseOperator(expr)
	if err != nil {
		return &CompileError{Category: category, Index: index, Message: err.Error()}
	}

	regoCondition, err := operatorToRego(op, arg)
	if err != nil {
		return &CompileError{Category: category, Index: index, Message: err.Error()}
	}

	// Escape double quotes in message for Rego string literal
	escapedMsg := strings.ReplaceAll(rule.Message, `"`, `\"`)

	fmt.Fprintf(b, "# Rule: %s - %s\n", category, escapedMsg)
	fmt.Fprintf(b, "%s contains msg if {\n", ruleSet)
	fmt.Fprintf(b, "    some cap in input.capabilities.%s\n", category)
	fmt.Fprintf(b, "    %s\n", regoCondition)

	if len(rule.Except) > 0 {
		quoted := make([]string, len(rule.Except))
		for i, ex := range rule.Except {
			quoted[i] = fmt.Sprintf("%q", ex)
		}
		fmt.Fprintf(b, "    not cap in {%s}\n", strings.Join(quoted, ", "))
	}

	fmt.Fprintf(b, "    msg := %q\n", rule.Message)
	b.WriteString("}\n\n")

	return nil
}

// parseOperator extracts operator name and argument from format: operator("argument")
func parseOperator(expr string) (string, string, error) {
	parenIdx := strings.Index(expr, "(")
	if parenIdx < 0 {
		return "", "", fmt.Errorf("invalid operator expression: %q (missing opening parenthesis)", expr)
	}

	op := expr[:parenIdx]
	rest := expr[parenIdx:]

	// Expect ("argument")
	if len(rest) < 4 || rest[0] != '(' || rest[1] != '"' || rest[len(rest)-1] != ')' || rest[len(rest)-2] != '"' {
		return "", "", fmt.Errorf("invalid operator expression: %q (expected format: operator(\"arg\"))", expr)
	}

	arg := rest[2 : len(rest)-2]
	if arg == "" {
		return "", "", fmt.Errorf("invalid operator expression: %q (empty argument)", expr)
	}

	// Security: reject arguments containing characters that could enable Rego injection.
	// Capability strings should only contain printable ASCII without quotes or backslashes.
	if strings.ContainsAny(arg, "\\\n\r\t\"") {
		return "", "", fmt.Errorf("invalid operator argument: %q (contains disallowed characters)", arg)
	}

	return op, arg, nil
}

// operatorToRego maps a DSL operator to a Rego condition.
func operatorToRego(op, arg string) (string, error) {
	switch op {
	case "contains":
		return fmt.Sprintf("contains(cap, %q)", arg), nil
	case "any":
		return fmt.Sprintf("startswith(cap, %q)", arg), nil
	default:
		return "", fmt.Errorf("unknown operator: %q (supported: contains, any)", op)
	}
}
