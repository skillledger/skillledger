package dsl

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// validCategory matches only lowercase alphanumeric and underscore — safe for Rego identifiers.
var validCategory = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

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
		if !validCategory.MatchString(category) {
			return "", fmt.Errorf("invalid category name %q: must match [a-z][a-z0-9_]*", category)
		}
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

// allowedRuntimeFields defines the valid field names for runtime-rules expressions.
var allowedRuntimeFields = map[string]bool{
	"destination": true,
	"tool":        true,
	"resource":    true,
	"method":      true,
}

// CompileRuntime transforms a RuntimeRuleSet into valid Rego source code.
// The output uses package skillledger.runtime_policy and import rego.v1.
// Returns empty string and nil error if rules is nil.
func CompileRuntime(rules *RuntimeRuleSet) (string, error) {
	if rules == nil {
		return "", nil
	}

	var b strings.Builder

	// Header
	b.WriteString("package skillledger.runtime_policy\n\n")
	b.WriteString("import rego.v1\n\n")

	// Block rules -> deny
	for i, expr := range rules.Block {
		field, op, arg, err := parseRuntimeExpr(expr)
		if err != nil {
			return "", fmt.Errorf("runtime-rules.block[%d]: %w", i, err)
		}
		condition, err := runtimeExprToRego(field, op, arg)
		if err != nil {
			return "", fmt.Errorf("runtime-rules.block[%d]: %w", i, err)
		}
		fmt.Fprintf(&b, "# Block: %s\n", expr)
		b.WriteString("deny contains msg if {\n")
		fmt.Fprintf(&b, "    %s\n", condition)
		fmt.Fprintf(&b, "    msg := %q\n", expr)
		b.WriteString("}\n\n")
	}

	// Warn rules -> warnings
	for i, expr := range rules.Warn {
		field, op, arg, err := parseRuntimeExpr(expr)
		if err != nil {
			return "", fmt.Errorf("runtime-rules.warn[%d]: %w", i, err)
		}
		condition, err := runtimeExprToRego(field, op, arg)
		if err != nil {
			return "", fmt.Errorf("runtime-rules.warn[%d]: %w", i, err)
		}
		fmt.Fprintf(&b, "# Warn: %s\n", expr)
		b.WriteString("warnings contains msg if {\n")
		fmt.Fprintf(&b, "    %s\n", condition)
		fmt.Fprintf(&b, "    msg := %q\n", expr)
		b.WriteString("}\n\n")
	}

	// Log rules -> log_entries
	for i, expr := range rules.Log {
		field, op, arg, err := parseRuntimeExpr(expr)
		if err != nil {
			return "", fmt.Errorf("runtime-rules.log[%d]: %w", i, err)
		}
		condition, err := runtimeExprToRego(field, op, arg)
		if err != nil {
			return "", fmt.Errorf("runtime-rules.log[%d]: %w", i, err)
		}
		fmt.Fprintf(&b, "# Log: %s\n", expr)
		b.WriteString("log_entries contains msg if {\n")
		fmt.Fprintf(&b, "    %s\n", condition)
		fmt.Fprintf(&b, "    msg := %q\n", expr)
		b.WriteString("}\n\n")
	}

	return b.String(), nil
}

// parseRuntimeExpr parses a runtime-rules expression of the form:
//
//	<field> <operator> <argument>
//
// Supported fields: destination, tool, resource, method
// Supported operators: contains, any, except
// Arguments: quoted string for contains, JSON array for any/except
func parseRuntimeExpr(expr string) (field, op, arg string, err error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return "", "", "", fmt.Errorf("empty expression")
	}

	// Split on first space to get field
	spaceIdx := strings.IndexByte(expr, ' ')
	if spaceIdx < 0 {
		return "", "", "", fmt.Errorf("invalid expression: %q (expected: <field> <operator> <argument>)", expr)
	}
	field = expr[:spaceIdx]
	rest := strings.TrimSpace(expr[spaceIdx+1:])

	// Validate field
	if !allowedRuntimeFields[field] {
		supported := make([]string, 0, len(allowedRuntimeFields))
		for k := range allowedRuntimeFields {
			supported = append(supported, k)
		}
		sort.Strings(supported)
		return "", "", "", fmt.Errorf("unsupported field: %q (supported: %s)", field, strings.Join(supported, ", "))
	}

	// Split on next space to get operator
	spaceIdx = strings.IndexByte(rest, ' ')
	if spaceIdx < 0 {
		return "", "", "", fmt.Errorf("invalid expression: %q (expected: <field> <operator> <argument>)", expr)
	}
	op = rest[:spaceIdx]
	arg = strings.TrimSpace(rest[spaceIdx+1:])

	// Validate operator
	switch op {
	case "contains", "any", "except":
		// valid
	default:
		return "", "", "", fmt.Errorf("unsupported operator: %q (supported: contains, any, except)", op)
	}

	// Extract and validate argument based on operator
	switch op {
	case "contains":
		// Expect quoted string: "value"
		if len(arg) < 2 || arg[0] != '"' || arg[len(arg)-1] != '"' {
			return "", "", "", fmt.Errorf("contains argument must be a quoted string: %s", arg)
		}
		arg = arg[1 : len(arg)-1]
		if arg == "" {
			return "", "", "", fmt.Errorf("empty argument in expression: %q", expr)
		}
		// Security: reject injection characters (same as parseOperator)
		if strings.ContainsAny(arg, "\\\n\r\t\"") {
			return "", "", "", fmt.Errorf("invalid argument: %q (contains disallowed characters)", arg)
		}
	case "any", "except":
		// Expect JSON array: ["a", "b"]
		if len(arg) < 2 || arg[0] != '[' || arg[len(arg)-1] != ']' {
			return "", "", "", fmt.Errorf("%s argument must be a JSON array: %s", op, arg)
		}
		// Parse as JSON to validate
		var items []string
		if err := json.Unmarshal([]byte(arg), &items); err != nil {
			return "", "", "", fmt.Errorf("invalid JSON array in %s: %w", op, err)
		}
		if len(items) == 0 {
			return "", "", "", fmt.Errorf("empty array in %s expression", op)
		}
		// Security: reject injection characters in each item
		for _, item := range items {
			if strings.ContainsAny(item, "\\\n\r\t\"") {
				return "", "", "", fmt.Errorf("invalid array element: %q (contains disallowed characters)", item)
			}
		}
		// Normalize: store as comma-separated for Rego generation
		// Keep original JSON arg for runtimeExprToRego to parse
	}

	return field, op, arg, nil
}

// runtimeExprToRego maps a parsed runtime expression to a Rego condition.
func runtimeExprToRego(field, op, arg string) (string, error) {
	inputPath := "input.action." + field

	switch op {
	case "contains":
		// If arg contains *, use glob.match; otherwise use contains builtin
		if strings.Contains(arg, "*") {
			return fmt.Sprintf("glob.match(%q, [\".\"], %s)", arg, inputPath), nil
		}
		return fmt.Sprintf("contains(%s, %q)", inputPath, arg), nil
	case "any":
		// Parse JSON array and build Rego set membership
		var items []string
		if err := json.Unmarshal([]byte(arg), &items); err != nil {
			return "", fmt.Errorf("invalid JSON array: %w", err)
		}
		quoted := make([]string, len(items))
		for i, item := range items {
			quoted[i] = fmt.Sprintf("%q", item)
		}
		return fmt.Sprintf("%s in {%s}", inputPath, strings.Join(quoted, ", ")), nil
	case "except":
		// Parse JSON array and build negated Rego set membership
		var items []string
		if err := json.Unmarshal([]byte(arg), &items); err != nil {
			return "", fmt.Errorf("invalid JSON array: %w", err)
		}
		quoted := make([]string, len(items))
		for i, item := range items {
			quoted[i] = fmt.Sprintf("%q", item)
		}
		return fmt.Sprintf("not %s in {%s}", inputPath, strings.Join(quoted, ", ")), nil
	default:
		return "", fmt.Errorf("unsupported operator: %q", op)
	}
}
