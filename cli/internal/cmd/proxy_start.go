package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"

	"github.com/skillledger/skillledger/internal/policy/dsl"
	"github.com/skillledger/skillledger/internal/proxy"
	"github.com/skillledger/skillledger/internal/report"
	"github.com/skillledger/skillledger/internal/signer"
	"github.com/skillledger/skillledger/internal/tlog"
	"github.com/skillledger/skillledger/internal/verify"
	yaraengine "github.com/skillledger/skillledger/internal/yara"
)

var proxyStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the runtime proxy",
	Long: `Starts the SkillLedger MITM proxy on the configured port (default 8118).
The proxy runs in the foreground and shuts down on SIGTERM or SIGINT.

On first start, a local ECDSA P-256 CA certificate is generated for HTTPS
interception. Run 'skillledger proxy trust' to install it in the system
trust store.`,
	RunE: runProxyStart,
}

func runProxyStart(cmd *cobra.Command, args []string) error {
	// Wait for background threat sync (D-04: 2s timeout)
	cacheDir := threatCacheDir()
	if threatSyncer != nil {
		threatSyncer.WaitForSync(2 * time.Second)
	}
	printThreatFreshness(cacheDir)

	port, _ := cmd.Flags().GetInt("port")
	logSize, _ := cmd.Flags().GetInt("decision-log-size")
	preset, _ := cmd.Flags().GetString("preset")
	manifestDir, _ := cmd.Flags().GetString("manifest-dir")
	policyFile, _ := cmd.Flags().GetString("policy-file")
	allowlistPath, _ := cmd.Flags().GetString("injection-allowlist")
	deepScan, _ := cmd.Flags().GetBool("deep-scan")
	streamableMCPURL, _ := cmd.Flags().GetString("streamable-mcp-url")
	lockfileDir, _ := cmd.Flags().GetString("lockfile-dir")
	tlogURL, _ := cmd.Flags().GetString("tlog-url")
	yaraRulesDir, _ := cmd.Flags().GetString("yara-rules")
	sarifOnShutdown, _ := cmd.Flags().GetString("sarif-on-shutdown")
	baseDir := proxyBaseDir()

	// Check if proxy is already running.
	running, pid := proxy.IsProxyRunning(afero.NewOsFs(), baseDir)
	if running {
		return fmt.Errorf("proxy already running (PID %d)", pid)
	}

	// Apply org policy if available (D-12: org policy overrides local for proxy)
	if orgSyncer != nil {
		orgSyncer.WaitForSync(2 * time.Second)
		orgPolicyPath := orgSyncer.CachedPolicyPath()
		if _, statErr := os.Stat(orgPolicyPath); statErr == nil {
			if policyFile == "" {
				policyFile = orgPolicyPath
				log.Info().Str("policy", orgPolicyPath).Msg("using org policy for proxy")
			} else {
				log.Info().Str("org_policy", orgPolicyPath).Str("local_policy", policyFile).Msg("org policy overrides local policy for proxy")
				policyFile = orgPolicyPath
			}
		}
	}

	// Build layered policy config: defaults < user config < project config < CLI flags.
	config := proxy.DefaultPolicyConfig()

	// Check well-known paths: user-level then project-level (later overrides earlier).
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

	// Load explicit policy file if specified.
	if policyFile != "" {
		data, err := os.ReadFile(policyFile)
		if err != nil {
			return fmt.Errorf("reading policy file: %w", err)
		}
		fileConfig, err := proxy.LoadPolicyConfig(data)
		if err != nil {
			return fmt.Errorf("parsing policy file: %w", err)
		}
		config = proxy.MergePolicyConfigs(config, fileConfig)
	}

	// CLI flag overrides config file preset.
	if cmd.Flags().Changed("preset") {
		config.Preset = preset
	}

	// Parse DSL runtime-rules from the explicit policy file (if provided).
	// dsl.Parse requires a version:1 DSL file; plain PolicyConfig YAML will
	// fail parsing -- that is expected and silently ignored.
	var extraModules map[string]string
	if policyFile != "" {
		data, _ := os.ReadFile(policyFile) // already read above; re-read is cheap
		if dslPolicy, dslErr := dsl.Parse(data); dslErr == nil {
			if dslPolicy.RuntimeRules != nil {
				rego, compileErr := dsl.CompileRuntime(dslPolicy.RuntimeRules)
				if compileErr != nil {
					log.Warn().Err(compileErr).Msg("failed to compile DSL runtime-rules to Rego")
				} else if rego != "" {
					extraModules = map[string]string{
						"skillledger.runtime_policy": rego,
					}
					log.Info().Int("modules", len(extraModules)).Msg("compiled runtime-rules to Rego")
				}
			}
		}
		// If dsl.Parse fails, the file is a plain PolicyConfig -- no action needed.
	}

	opts := []proxy.ServerOption{
		proxy.WithPort(port),
		proxy.WithBaseDir(baseDir),
		proxy.WithDecisionLogSize(logSize),
		proxy.WithLogger(log.Logger),
		proxy.WithPolicyConfig(config),
	}

	if manifestDir != "" {
		opts = append(opts, proxy.WithManifestDir(manifestDir))
	}
	if allowlistPath != "" {
		opts = append(opts, proxy.WithInjectionAllowlist(allowlistPath))
	}
	if deepScan {
		opts = append(opts, proxy.WithDeepScan(true))
	}
	if streamableMCPURL != "" {
		opts = append(opts, proxy.WithStreamableMCPURL(streamableMCPURL))
	}
	if lockfileDir != "" {
		opts = append(opts, proxy.WithLockfileDir(lockfileDir))

		// Construct v1 verify pipeline for trust verification.
		sigVerifier := signer.NewVerifier()
		log.Warn().Msg("proxy verifier has no identity constraints -- accepts any valid Sigstore signature; use --expected-issuer and --expected-identity for production")
		tlogClient := tlog.NewClient(tlog.WithServiceURL(tlogURL))
		pipeline := verify.NewPipeline(sigVerifier, tlogClient, nil)
		opts = append(opts, proxy.WithVerifyPipeline(pipeline))
	}
	if yaraRulesDir != "" {
		opts = append(opts, proxy.WithYARARulesDir(yaraRulesDir))
	} else {
		// Try loading YARA rules from sync cache when no explicit --yara-rules
		if rules, loadErr := yaraengine.LoadCachedRules(cacheDir); loadErr == nil && len(rules) > 0 {
			if _, compileErr := yaraengine.NewEngineFromRules(rules); compileErr == nil {
				// Cache has valid rules -- pass cache dir so proxy can load them
				opts = append(opts, proxy.WithYARARulesDir(filepath.Join(cacheDir)))
				log.Debug().Int("rules", len(rules)).Msg("YARA rules loaded from sync cache for proxy")
			} else {
				log.Debug().Err(compileErr).Msg("Failed to compile cached YARA rules for proxy, skipping")
			}
		}
	}
	if extraModules != nil {
		opts = append(opts, proxy.WithExtraModules(extraModules))
	}

	// Always wire violation log to capture entries with findings.
	violationLogPath := filepath.Join(baseDir, "proxy", "violations.jsonl")
	opts = append(opts, proxy.WithViolationLog(violationLogPath))

	server := proxy.NewProxyServer(opts...)

	log.Info().Int("port", port).Msgf("Starting proxy on 127.0.0.1:%d", port)
	log.Info().Str("ca_cert", proxy.CACertPath(baseDir)).Msg("CA certificate location")
	log.Info().Str("preset", config.Preset).Msg("runtime policy preset")
	if manifestDir != "" {
		log.Info().Str("manifest_dir", manifestDir).Msg("loading skill manifests from directory")
	}
	if streamableMCPURL != "" {
		log.Info().Str("streamable_mcp_url", streamableMCPURL).Msg("Streamable HTTP MCP proxy -> /mcp")
	}
	if lockfileDir != "" {
		log.Info().Str("lockfile_dir", lockfileDir).Str("tlog_url", tlogURL).Msg("provenance verification enabled")
	}
	if yaraRulesDir != "" {
		log.Info().Str("yara_rules", yaraRulesDir).Msg("YARA rules directory configured for runtime scanning")
	}
	log.Info().Msg("Run `skillledger proxy trust` to install CA into system trust store")

	// Handle SIGTERM/SIGINT for graceful shutdown.
	ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	err := server.Start(ctx)

	// Flush accumulated violation events to org service on shutdown (D-13)
	if eventReporter != nil && currentOrgSlug != "" {
		log.Debug().Msg("proxy shutdown: waiting for event report flush")
		eventReporter.WaitForReport(2 * time.Second)
	}

	// Generate SARIF report on shutdown if requested.
	if sarifOnShutdown != "" {
		decLogPath := filepath.Join(baseDir, "proxy", "decisions.jsonl")
		entries, readErr := readDecisionEntries(decLogPath)
		if readErr != nil {
			log.Warn().Err(readErr).Msg("failed to read decisions for SARIF on shutdown")
		} else {
			f, createErr := os.Create(sarifOnShutdown)
			if createErr != nil {
				log.Warn().Err(createErr).Str("path", sarifOnShutdown).Msg("failed to create SARIF output file")
			} else {
				if sarifErr := report.GenerateRuntimeSARIF(f, entries); sarifErr != nil {
					log.Warn().Err(sarifErr).Msg("failed to generate SARIF on shutdown")
				} else {
					log.Info().Str("path", sarifOnShutdown).Msg("SARIF report written on shutdown")
				}
				f.Close()
			}
		}
	}

	return err
}

func init() {
	// Default port from env var or 8118.
	defaultPort := 8118
	if envPort := os.Getenv("SKILLLEDGER_PROXY_PORT"); envPort != "" {
		if p, err := strconv.Atoi(envPort); err == nil && p > 0 && p < 65536 {
			defaultPort = p
		}
	}

	proxyStartCmd.Flags().IntP("port", "p", defaultPort, "proxy listening port")
	proxyStartCmd.Flags().Int("decision-log-size", 1000, "number of decisions to keep in memory")
	proxyStartCmd.Flags().String("preset", "moderate", "runtime policy preset (strict/moderate/permissive)")
	proxyStartCmd.Flags().String("manifest-dir", "", "directory containing skill manifests (skillledger.yaml files)")
	proxyStartCmd.Flags().String("policy-file", "", "path to policy DSL YAML file with runtime-rules")

	// Phase 12: New flags for MCP protection.
	proxyStartCmd.Flags().String("injection-allowlist", "", "path to injection allowlist YAML for false positive suppression")
	proxyStartCmd.Flags().Bool("deep-scan", false, "always run ML classifier (not just on inconclusive heuristic)")
	proxyStartCmd.Flags().String("streamable-mcp-url", "", "target Streamable HTTP MCP server URL (e.g., ws://localhost:3000/mcp)")

	// Phase 13: Provenance-aware policy flags.
	proxyStartCmd.Flags().String("lockfile-dir", "", "directory containing skill lockfiles for provenance verification")
	proxyStartCmd.Flags().String("tlog-url", "http://localhost:8080", "transparency log service URL for provenance verification")

	// Phase 14: YARA and reporting flags.
	proxyStartCmd.Flags().String("yara-rules", "", "path to YARA rules directory for runtime scanning")
	proxyStartCmd.Flags().String("sarif-on-shutdown", "", "path to write SARIF report on proxy shutdown")
}
