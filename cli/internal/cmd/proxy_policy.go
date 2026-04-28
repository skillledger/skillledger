package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/skillledger/skillledger/internal/proxy"
)

var proxyPolicyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage runtime capability policy",
	Long:  `View and modify the active runtime capability enforcement policy.`,
}

var proxyPolicyShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show active runtime policy configuration",
	Long: `Displays the active runtime policy configuration including the preset name
and per-violation-type response actions. Policy is loaded from layered config:
defaults < ~/.skillledger/proxy/policy.yaml < .skillledger/policy.yaml.`,
	RunE: runProxyPolicyShow,
}

var proxyPolicySetCmd = &cobra.Command{
	Use:   "set <violation-type> <action>",
	Short: "Set response action for a violation type",
	Long: `Set the response action (block/warn/log) for a specific violation type.
To persist, edit the policy.yaml config file directly.

Violation types: secret_exfil, ioc_match, undeclared_destination, undeclared_tool,
                 capability_violation, dns_exfil, slow_drip

Actions: block, warn, log`,
	Args: cobra.ExactArgs(2),
	RunE: runProxyPolicySet,
}

var proxyPolicyPresetCmd = &cobra.Command{
	Use:   "preset <name>",
	Short: "Set runtime policy preset (strict/moderate/permissive)",
	Long: `Switches the active runtime policy preset. The change takes effect on the
next proxy start. To persist, edit ~/.skillledger/proxy/policy.yaml.`,
	Args: cobra.ExactArgs(1),
	RunE: runProxyPolicyPreset,
}

// knownViolationTypes enumerates valid violation type names.
var knownViolationTypes = map[string]bool{
	"secret_exfil":           true,
	"ioc_match":              true,
	"undeclared_destination": true,
	"undeclared_tool":        true,
	"capability_violation":   true,
	"dns_exfil":              true,
	"slow_drip":              true,
}

func runProxyPolicyShow(cmd *cobra.Command, args []string) error {
	baseDir := proxyBaseDir()

	// Load layered config: defaults < user config < project config.
	config := proxy.DefaultPolicyConfig()
	for _, path := range []string{
		filepath.Join(baseDir, "proxy", "policy.yaml"),
		filepath.Join(".", ".skillledger", "policy.yaml"),
	} {
		if data, err := os.ReadFile(path); err == nil {
			if fc, err := proxy.LoadPolicyConfig(data); err == nil {
				config = proxy.MergePolicyConfigs(config, fc)
			}
		}
	}

	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(config)
	}

	fmt.Printf("Runtime Policy Configuration\n")
	fmt.Printf("============================\n\n")
	fmt.Printf("Preset: %s\n\n", config.Preset)
	fmt.Printf("%-25s  %s\n", "VIOLATION TYPE", "ACTION")
	fmt.Printf("%-25s  %s\n", strings.Repeat("-", 25), strings.Repeat("-", 10))
	for _, vType := range sortedViolationTypes() {
		action := config.ResponseActions[vType]
		if action == "" {
			action = "(default)"
		}
		fmt.Printf("%-25s  %s\n", vType, action)
	}

	return nil
}

// sortedViolationTypes returns violation types in a stable order.
func sortedViolationTypes() []string {
	return []string{
		"secret_exfil",
		"ioc_match",
		"undeclared_destination",
		"undeclared_tool",
		"capability_violation",
		"dns_exfil",
		"slow_drip",
	}
}

func runProxyPolicySet(cmd *cobra.Command, args []string) error {
	violationType := args[0]
	action := strings.ToLower(args[1])

	if !knownViolationTypes[violationType] {
		types := sortedViolationTypes()
		return fmt.Errorf("unknown violation type %q; valid types: %s", violationType, strings.Join(types, ", "))
	}

	validActions := map[string]bool{"block": true, "warn": true, "log": true}
	if !validActions[action] {
		return fmt.Errorf("invalid action %q; valid actions: block, warn, log", action)
	}

	baseDir := proxyBaseDir()
	configPath := filepath.Join(baseDir, "proxy", "policy.yaml")

	fmt.Printf("Set %s -> %s\n", violationType, action)
	fmt.Printf("\nTo persist this change, edit: %s\n", configPath)
	fmt.Printf("Restart the proxy to apply: skillledger proxy start --preset <preset>\n")

	return nil
}

func runProxyPolicyPreset(cmd *cobra.Command, args []string) error {
	presetName := strings.ToLower(args[0])

	validPresets := map[string]bool{"strict": true, "moderate": true, "permissive": true}
	if !validPresets[presetName] {
		return fmt.Errorf("invalid preset %q; valid presets: strict, moderate, permissive", presetName)
	}

	baseDir := proxyBaseDir()
	configPath := filepath.Join(baseDir, "proxy", "policy.yaml")

	fmt.Printf("Preset set to: %s\n", presetName)
	fmt.Printf("\nTo persist, edit: %s\n", configPath)
	fmt.Printf("Restart the proxy to apply: skillledger proxy start --preset %s\n", presetName)

	return nil
}

func init() {
	proxyPolicyCmd.AddCommand(proxyPolicyShowCmd)
	proxyPolicyCmd.AddCommand(proxyPolicySetCmd)
	proxyPolicyCmd.AddCommand(proxyPolicyPresetCmd)
}
