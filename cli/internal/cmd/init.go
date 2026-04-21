package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/spf13/cobra"
)

var validKinds = []string{
	"claude-code-skill", "mcp-server", "openclaw-plugin",
	"anthropic-skill", "openai-tool", "codex-tool",
	"opencode", "generic",
}

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Generate a starter skillledger.yaml for a chosen ecosystem",
	Long:  "Creates a skillledger.yaml manifest template in the current directory for the specified ecosystem kind.",
	RunE: func(cmd *cobra.Command, args []string) error {
		kind, _ := cmd.Flags().GetString("kind")
		if kind == "" {
			return fmt.Errorf("--kind is required. Valid kinds: %s", strings.Join(validKinds, ", "))
		}

		validKind := false
		for _, k := range validKinds {
			if k == kind {
				validKind = true
				break
			}
		}
		if !validKind {
			return fmt.Errorf("invalid kind %q. Valid kinds: %s", kind, strings.Join(validKinds, ", "))
		}

		outputFile := "skillledger.yaml"
		// Security: ensure output path stays in CWD (T-01-03)
		absPath, err := filepath.Abs(outputFile)
		if err != nil {
			return fmt.Errorf("resolving output path: %w", err)
		}
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("getting working directory: %w", err)
		}
		if !strings.HasPrefix(absPath, cwd+string(os.PathSeparator)) && absPath != cwd {
			return fmt.Errorf("output path escapes working directory")
		}

		if _, err := os.Stat(outputFile); err == nil {
			return fmt.Errorf("%s already exists. Remove it first or use a different directory", outputFile)
		}

		tmpl := template.Must(template.New("manifest").Parse(manifestTemplate))

		f, err := os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("creating %s: %w", outputFile, err)
		}
		defer f.Close()

		data := map[string]string{
			"Kind": kind,
		}
		if err := tmpl.Execute(f, data); err != nil {
			return fmt.Errorf("writing template: %w", err)
		}

		fmt.Fprintf(os.Stdout, "Created %s (kind: %s)\n", outputFile, kind)
		return nil
	},
}

// Template uses quoted version string to avoid YAML type coercion
const manifestTemplate = `skillledger: 1
id: com.example.my-skill
version: "0.1.0"
kind: {{.Kind}}
source:
  repository: https://github.com/example/my-skill
  ref: main
capabilities: {}
# profile:
#   Add ecosystem-specific fields here
`

func init() {
	initCmd.Flags().StringP("kind", "k", "", "ecosystem kind (e.g., mcp-server, claude-code-skill)")
	_ = initCmd.MarkFlagRequired("kind")
	rootCmd.AddCommand(initCmd)
}
