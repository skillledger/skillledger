package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/elazarl/goproxy"
	"github.com/rs/zerolog"
	"github.com/skillledger/skillledger/internal/ioc"
	"github.com/skillledger/skillledger/internal/manifest"
	"github.com/skillledger/skillledger/internal/verify"
	"github.com/spf13/afero"
	"gopkg.in/yaml.v3"
)

const (
	defaultPort           = 8118
	defaultDecisionLogCap = 1000
	proxySubDir           = "proxy"
	pidFileName           = "proxy.pid"
	portFileName          = "proxy.port"
)

// ServerOption configures a ProxyServer.
type ServerOption func(*ProxyServer)

// ProxyServer is an HTTP/HTTPS MITM proxy that intercepts skill traffic.
type ProxyServer struct {
	fs             afero.Fs
	baseDir        string
	port           int
	decisionLog    *DecisionLog
	handler        *Handler
	proxy          *goproxy.ProxyHttpServer
	listener       net.Listener
	logger         zerolog.Logger
	logSize        int
	policyConfig   *PolicyConfig
	manifestDir    string
	capabilityEval *RuntimeEvaluator
	profiler       *Profiler

	// Phase 12: MCP protection components.
	pinStore        *ToolPinStore      // tool definition pinning for rug-pull detection
	injScanner      *InjectionScanner  // prompt injection scanner (also in HTTP pipeline)
	mlCloser        io.Closer          // ML classifier resource handle (nil if no ML)
	streamableURL   string             // target URL for Streamable HTTP MCP proxy
	streamableProxy *StreamableProxy   // Streamable HTTP MCP proxy instance

	// Phase 12: options applied in NewProxyServer.
	injAllowlistPath string // path to injection allowlist YAML
	deepScan         bool   // always run ML classifier

	// Phase 13: Provenance-aware policy components.
	trustVerifier  *TrustVerifier     // session-scoped trust tier verifier (nil if no lockfile-dir)
	lockfileDir    string             // directory containing skill lockfiles
	verifyPipeline *verify.Pipeline   // v1 verification pipeline for trust verification

	// Phase 15: DSL runtime-rules extra Rego modules.
	extraModules map[string]string // compiled Rego from DSL runtime-rules

	// Phase 14: YARA and violation logging.
	yaraRulesDir    string           // path to YARA rules directory
	violationLogPath string          // path to violations.jsonl
	violationWriter *ViolationWriter // append-only violation JSONL writer
}

// WithPort sets the proxy listen port.
func WithPort(port int) ServerOption {
	return func(s *ProxyServer) {
		s.port = port
	}
}

// WithBaseDir sets the base directory for CA, PID, and port files.
func WithBaseDir(dir string) ServerOption {
	return func(s *ProxyServer) {
		s.baseDir = dir
	}
}

// WithFs sets the filesystem implementation (for testing).
func WithFs(fs afero.Fs) ServerOption {
	return func(s *ProxyServer) {
		s.fs = fs
	}
}

// WithDecisionLogSize sets the decision log ring buffer capacity.
func WithDecisionLogSize(size int) ServerOption {
	return func(s *ProxyServer) {
		s.logSize = size
	}
}

// WithLogger sets the zerolog logger for the proxy server.
func WithLogger(logger zerolog.Logger) ServerOption {
	return func(s *ProxyServer) {
		s.logger = logger
	}
}

// WithPolicyConfig sets the runtime capability policy configuration.
func WithPolicyConfig(config *PolicyConfig) ServerOption {
	return func(s *ProxyServer) {
		s.policyConfig = config
	}
}

// WithManifestDir sets the directory containing skill manifests (skillledger.yaml files).
func WithManifestDir(dir string) ServerOption {
	return func(s *ProxyServer) {
		s.manifestDir = dir
	}
}

// WithInjectionAllowlist sets the path to the injection allowlist YAML file.
func WithInjectionAllowlist(path string) ServerOption {
	return func(s *ProxyServer) {
		s.injAllowlistPath = path
	}
}

// WithDeepScan enables always-on ML classification (not just on inconclusive heuristic).
func WithDeepScan(enabled bool) ServerOption {
	return func(s *ProxyServer) {
		s.deepScan = enabled
	}
}

// WithStreamableMCPURL sets the target Streamable HTTP MCP server URL.
// When set, a StreamableProxy is created and registered on the /mcp endpoint.
func WithStreamableMCPURL(url string) ServerOption {
	return func(s *ProxyServer) {
		s.streamableURL = url
	}
}

// WithLockfileDir sets the directory containing skill lockfiles for provenance verification.
// When set along with a verify pipeline, a TrustVerifier is created to assign trust tiers.
func WithLockfileDir(dir string) ServerOption {
	return func(s *ProxyServer) {
		s.lockfileDir = dir
	}
}

// WithVerifyPipeline sets the v1 verification pipeline used by TrustVerifier.
func WithVerifyPipeline(p *verify.Pipeline) ServerOption {
	return func(s *ProxyServer) {
		s.verifyPipeline = p
	}
}

// WithYARARulesDir sets the path to YARA rules directory for runtime scanning.
// If set, a YARAScanner is created and added to the scan pipeline.
func WithYARARulesDir(dir string) ServerOption {
	return func(s *ProxyServer) {
		s.yaraRulesDir = dir
	}
}

// WithExtraModules sets additional Rego modules (e.g., compiled DSL runtime-rules)
// that are passed to NewRuntimeEvaluator alongside the preset Rego.
func WithExtraModules(modules map[string]string) ServerOption {
	return func(s *ProxyServer) {
		s.extraModules = modules
	}
}

// WithViolationLog sets the path to the violations JSONL file.
// A ViolationWriter is created during Start() using the server's afero.Fs.
func WithViolationLog(path string) ServerOption {
	return func(s *ProxyServer) {
		s.violationLogPath = path
	}
}

// NewProxyServer creates a new proxy server with the given options.
func NewProxyServer(opts ...ServerOption) *ProxyServer {
	home, _ := os.UserHomeDir()
	s := &ProxyServer{
		fs:      afero.NewOsFs(),
		baseDir: filepath.Join(home, ".skillledger"),
		port:    defaultPort,
		logSize: defaultDecisionLogCap,
		logger:  zerolog.Nop(),
	}

	for _, opt := range opts {
		opt(s)
	}

	// Initialize detection scanners.
	var scanners []Scanner

	// Secret scanner with bundled patterns.
	patterns := LoadPatterns()
	secretScanner := NewSecretScanner(patterns)
	scanners = append(scanners, secretScanner)

	// Network scanner with IOC domain database.
	iocDB, err := ioc.Load()
	if err != nil {
		s.logger.Warn().Err(err).Msg("failed to load IOC database -- network scanner disabled")
	} else {
		networkScanner := NewNetworkScanner(iocDB)
		scanners = append(scanners, networkScanner)
	}

	// DNS exfiltration scanner.
	dnsExfilScanner := NewDNSExfilScanner()
	scanners = append(scanners, dnsExfilScanner)

	// Cumulative entropy tracker.
	entropyTracker := NewEntropyTracker()
	scanners = append(scanners, entropyTracker)

	// Phase 12: Injection scanner for HTTP traffic.
	var allowlist *InjectionAllowlist
	if s.injAllowlistPath != "" {
		var loadErr error
		allowlist, loadErr = LoadInjectionAllowlist(s.injAllowlistPath)
		if loadErr != nil {
			s.logger.Warn().Err(loadErr).Str("path", s.injAllowlistPath).Msg("failed to load injection allowlist")
		}
	} else {
		// Try default path.
		allowlist, _ = LoadInjectionAllowlist(filepath.Join(s.baseDir, "injection-allowlist.yaml"))
	}
	injScanner := NewInjectionScanner(allowlist)
	if s.deepScan {
		injScanner.SetDeepScan(true)
	}
	scanners = append(scanners, injScanner)
	s.injScanner = injScanner

	// Phase 14: YARA scanner from user-supplied rules directory.
	if s.yaraRulesDir != "" {
		yaraScanner := NewYARAScanner(s.yaraRulesDir)
		if yaraScanner != nil {
			scanners = append(scanners, yaraScanner)
			s.logger.Info().Str("dir", s.yaraRulesDir).Msg("YARA scanner loaded into pipeline")
		}
	}

	pipeline := NewScanPipeline(scanners...)

	// Phase 12: Initialize ToolPinStore.
	pinStore := NewToolPinStore(filepath.Join(s.baseDir, "pins.json"))
	if loadErr := pinStore.Load(); loadErr != nil {
		s.logger.Warn().Err(loadErr).Msg("failed to load pin store -- starting fresh")
	}
	s.pinStore = pinStore

	// Phase 12: Optionally wire ML classifier (build-tag-safe).
	if closer := tryLoadMLClassifier(s.baseDir, injScanner, s.logger); closer != nil {
		s.mlCloser = closer
	}

	// Initialize auto-profiler.
	profiler := NewProfiler()
	s.profiler = profiler

	// Load policy config (default if none provided via option).
	if s.policyConfig == nil {
		s.policyConfig = DefaultPolicyConfig()
	}

	// Load manifests from manifest directory.
	manifests := make(map[string]*manifest.Manifest)
	if s.manifestDir != "" {
		loaded, loadErr := loadManifestsFromDir(s.fs, s.manifestDir)
		if loadErr != nil {
			s.logger.Warn().Err(loadErr).Str("dir", s.manifestDir).Msg("failed to load manifests")
		} else {
			manifests = loaded
			s.logger.Info().Int("manifests", len(manifests)).Msg("loaded skill manifests")
		}
	}

	// Initialize RuntimeEvaluator.
	capEval, evalErr := NewRuntimeEvaluator(s.policyConfig.Preset, manifests, s.policyConfig, profiler, s.extraModules)
	if evalErr != nil {
		s.logger.Warn().Err(evalErr).Msg("failed to initialize runtime evaluator -- capability enforcement disabled")
	} else {
		s.capabilityEval = capEval
		s.logger.Info().
			Str("preset", s.policyConfig.Preset).
			Int("manifests", len(manifests)).
			Msg("runtime capability evaluator initialized")
	}

	// Phase 13: Create TrustVerifier if lockfile directory and verify pipeline are provided.
	if s.lockfileDir != "" {
		if s.verifyPipeline != nil {
			ctx := context.Background()
			tv := NewTrustVerifier(ctx, s.verifyPipeline, s.fs, s.lockfileDir, s.logger)
			s.trustVerifier = tv
			s.logger.Info().
				Str("lockfile_dir", s.lockfileDir).
				Msg("trust verifier initialized for provenance-aware policy")
		} else {
			s.logger.Warn().
				Str("lockfile_dir", s.lockfileDir).
				Msg("lockfile-dir set but no verify pipeline provided -- trust verification disabled")
		}
	}

	// Phase 12: Create StreamableProxy if URL is configured.
	if s.streamableURL != "" {
		sp := NewStreamableProxy(s.streamableURL, nil, s.logger, s.pinStore, s.injScanner, s.policyConfig)
		s.streamableProxy = sp
		s.logger.Info().
			Str("streamable_mcp_url", s.streamableURL).
			Msg("Streamable HTTP MCP proxy created")
	}

	s.decisionLog = NewDecisionLog(s.logSize)

	// Wire decision log into StreamableProxy now that it exists.
	if s.streamableProxy != nil {
		s.streamableProxy.decisionLog = s.decisionLog
	}

	// Wire ViolationWriter into StreamableProxy (set later in Start() if violationLogPath is configured).
	// This is a forward reference -- the actual wiring happens in Start() after ViolationWriter creation.

	s.handler = NewHandler(s.decisionLog, pipeline, s.capabilityEval, s.trustVerifier, s.policyConfig, s.logger)
	s.proxy = goproxy.NewProxyHttpServer()

	s.logger.Info().
		Int("secret_patterns", len(patterns)).
		Int("scanners", len(scanners)).
		Msg("scanner pipeline initialized")

	return s
}

// loadManifestsFromDir reads all YAML files in the given directory and parses
// them as skill manifests. Malformed files are skipped with a warning log (T-11-12).
func loadManifestsFromDir(fs afero.Fs, dir string) (map[string]*manifest.Manifest, error) {
	entries, err := afero.ReadDir(fs, dir)
	if err != nil {
		return nil, fmt.Errorf("reading manifest directory: %w", err)
	}

	manifests := make(map[string]*manifest.Manifest)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		data, readErr := afero.ReadFile(fs, filepath.Join(dir, name))
		if readErr != nil {
			continue
		}
		var m manifest.Manifest
		if unmarshalErr := yaml.Unmarshal(data, &m); unmarshalErr != nil {
			continue
		}
		if m.ID == "" {
			continue
		}
		manifests[m.ID] = &m
	}

	return manifests, nil
}

// Port returns the configured port.
func (s *ProxyServer) Port() int {
	return s.port
}

// BaseDir returns the configured base directory.
func (s *ProxyServer) BaseDir() string {
	return s.baseDir
}

// DecisionLog returns the decision log for inspection.
func (s *ProxyServer) DecisionLog() *DecisionLog {
	return s.decisionLog
}

// PinStore returns the tool pin store.
func (s *ProxyServer) PinStore() *ToolPinStore {
	return s.pinStore
}

// InjectionScanner returns the injection scanner.
func (s *ProxyServer) InjectionScanner() *InjectionScanner {
	return s.injScanner
}

// StreamableProxy returns the Streamable HTTP MCP proxy (nil if not configured).
func (s *ProxyServer) StreamableProxy() *StreamableProxy {
	return s.streamableProxy
}

// Start initializes the CA, configures MITM, and starts listening.
// It blocks until the context is cancelled or Stop is called.
func (s *ProxyServer) Start(ctx context.Context) error {
	// Check for stale PID (T-09-05).
	if running, pid := IsProxyRunning(s.fs, s.baseDir); running {
		return fmt.Errorf("proxy already running (PID %d)", pid)
	}

	// Load or create CA certificate.
	ca, err := LoadOrCreateCA(s.fs, s.baseDir)
	if err != nil {
		return fmt.Errorf("load CA: %w", err)
	}

	// Configure per-connection MITM TLS (not global mutation per Pitfall 1).
	tlsConfigFunc := goproxy.TLSConfigFromCA(ca)
	s.proxy.OnRequest().HandleConnectFunc(
		func(host string, pCtx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
			return &goproxy.ConnectAction{
				Action:    goproxy.ConnectMitm,
				TLSConfig: tlsConfigFunc,
			}, host
		},
	)

	// Register request/response handlers.
	s.proxy.OnRequest().DoFunc(s.handler.OnRequest)
	s.proxy.OnResponse().DoFunc(s.handler.OnResponse)

	// Phase 12: Register StreamableProxy on /mcp endpoint for non-proxy requests.
	if s.streamableProxy != nil {
		s.proxy.NonproxyHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/mcp" {
				s.streamableProxy.ServeHTTP(w, r)
				return
			}
			// Default: serve a simple status for direct (non-proxy) requests.
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("SkillLedger proxy running"))
		})
		s.logger.Info().
			Str("streamable_mcp_url", s.streamableURL).
			Msg("Streamable HTTP MCP proxy registered on /mcp")
	}

	// Bind to localhost only (T-09-06).
	addr := fmt.Sprintf("127.0.0.1:%d", s.port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}
	s.listener = ln

	// Update port from listener (handles port 0 for tests).
	if tcpAddr, ok := ln.Addr().(*net.TCPAddr); ok {
		s.port = tcpAddr.Port
	}

	// Open decisions.jsonl for file-backed decision persistence.
	decisionLogPath := filepath.Join(s.baseDir, proxySubDir, "decisions.jsonl")
	decisionFile, err := os.OpenFile(decisionLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		s.logger.Warn().Err(err).Msg("failed to open decisions.jsonl -- explain command will not work")
	} else {
		s.decisionLog.SetFileWriter(decisionFile)
		defer decisionFile.Close()
	}

	// Phase 14: Create ViolationWriter for findings-only JSONL.
	if s.violationLogPath != "" {
		vw, vwErr := NewViolationWriter(s.fs, s.violationLogPath)
		if vwErr != nil {
			s.logger.Warn().Err(vwErr).Msg("failed to open violations.jsonl -- violation logging disabled")
		} else {
			s.violationWriter = vw
			s.handler.SetViolationWriter(vw)
			if s.streamableProxy != nil {
				s.streamableProxy.SetViolationWriter(vw)
			}
		}
	}

	// Write PID and port files (D-08).
	if err := writePIDFile(s.fs, s.baseDir); err != nil {
		s.logger.Warn().Err(err).Msg("failed to write PID file")
	}
	if err := writePortFile(s.fs, s.baseDir, s.port); err != nil {
		s.logger.Warn().Err(err).Msg("failed to write port file")
	}

	s.logger.Info().
		Int("port", s.port).
		Str("addr", ln.Addr().String()).
		Msg("proxy started")

	// Serve in a goroutine so we can handle context cancellation.
	server := &http.Server{Handler: s.proxy}
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(ln)
	}()

	select {
	case <-ctx.Done():
		s.logger.Info().Msg("proxy shutting down")
		_ = server.Close()
		s.cleanup()
		return nil
	case err := <-errCh:
		s.cleanup()
		if err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("proxy server: %w", err)
		}
		return nil
	}
}

// Stop closes the listener and cleans up PID/port files.
func (s *ProxyServer) Stop() error {
	if s.listener != nil {
		if err := s.listener.Close(); err != nil {
			return fmt.Errorf("close listener: %w", err)
		}
	}
	s.cleanup()
	return nil
}

// Addr returns the listener address, or empty string if not started.
func (s *ProxyServer) Addr() string {
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return ""
}

// Profiler returns the auto-profiler instance.
func (s *ProxyServer) Profiler() *Profiler { return s.profiler }

// RuntimeEvaluator returns the capability evaluator instance.
func (s *ProxyServer) RuntimeEvaluator() *RuntimeEvaluator { return s.capabilityEval }

// PolicyConfig returns the active policy configuration.
func (s *ProxyServer) PolicyConfig() *PolicyConfig { return s.policyConfig }

// TrustVerifier returns the trust verifier instance (nil if not configured).
func (s *ProxyServer) TrustVerifier() *TrustVerifier { return s.trustVerifier }

func (s *ProxyServer) cleanup() {
	// Phase 14: Close ViolationWriter.
	if s.violationWriter != nil {
		if err := s.violationWriter.Close(); err != nil {
			s.logger.Warn().Err(err).Msg("failed to close violation writer")
		}
	}

	// Phase 13: Close TrustVerifier to cancel in-flight verification goroutines.
	if s.trustVerifier != nil {
		s.trustVerifier.Close()
	}

	// Phase 12: Close ML classifier resources.
	if s.mlCloser != nil {
		s.mlCloser.Close()
	}

	// Phase 12: Save pin store on shutdown.
	if s.pinStore != nil {
		if err := s.pinStore.Save(); err != nil {
			s.logger.Warn().Err(err).Msg("failed to save pin store on shutdown")
		}
	}

	// Export profiles on shutdown (T-11-13: 0600 permissions).
	if s.profiler != nil {
		profiles := s.profiler.ExportAll()
		if len(profiles) > 0 {
			profileDir := filepath.Join(s.baseDir, "profiles")
			if err := s.fs.MkdirAll(profileDir, 0700); err != nil {
				s.logger.Warn().Err(err).Msg("failed to create profiles directory")
			} else {
				for _, m := range profiles {
					data, marshalErr := yaml.Marshal(m)
					if marshalErr != nil {
						s.logger.Warn().Err(marshalErr).Str("skill", m.ID).Msg("failed to marshal profile")
						continue
					}
					path := filepath.Join(profileDir, m.ID+".yaml")
					if writeErr := afero.WriteFile(s.fs, path, data, 0600); writeErr != nil {
						s.logger.Warn().Err(writeErr).Str("path", path).Msg("failed to write profile")
					} else {
						s.logger.Info().Str("skill", m.ID).Str("path", path).Msg("exported skill profile")
					}
				}
			}
		}
	}

	removePIDFile(s.fs, s.baseDir)
	removePortFile(s.fs, s.baseDir)
}

// writePIDFile writes the current process PID to the proxy directory.
func writePIDFile(fs afero.Fs, baseDir string) error {
	dir := filepath.Join(baseDir, proxySubDir)
	if err := fs.MkdirAll(dir, 0700); err != nil {
		return err
	}
	pidPath := filepath.Join(dir, pidFileName)
	return afero.WriteFile(fs, pidPath, []byte(strconv.Itoa(os.Getpid())), 0644)
}

// writePortFile writes the proxy listen port to the proxy directory.
func writePortFile(fs afero.Fs, baseDir string, port int) error {
	dir := filepath.Join(baseDir, proxySubDir)
	if err := fs.MkdirAll(dir, 0700); err != nil {
		return err
	}
	portPath := filepath.Join(dir, portFileName)
	return afero.WriteFile(fs, portPath, []byte(strconv.Itoa(port)), 0644)
}

// removePIDFile removes the PID file.
func removePIDFile(fs afero.Fs, baseDir string) {
	_ = fs.Remove(filepath.Join(baseDir, proxySubDir, pidFileName))
}

// removePortFile removes the port file.
func removePortFile(fs afero.Fs, baseDir string) {
	_ = fs.Remove(filepath.Join(baseDir, proxySubDir, portFileName))
}

// ReadPortFile reads the proxy port from the port file on disk.
func ReadPortFile(fs afero.Fs, baseDir string) (int, error) {
	portPath := filepath.Join(baseDir, proxySubDir, portFileName)
	data, err := afero.ReadFile(fs, portPath)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(data)))
}

// ReadPIDFile reads the proxy PID from the PID file on disk.
func ReadPIDFile(fs afero.Fs, baseDir string) (int, error) {
	pidPath := filepath.Join(baseDir, proxySubDir, pidFileName)
	data, err := afero.ReadFile(fs, pidPath)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(data)))
}

// RemovePIDFile removes the PID file (for cleaning stale PIDs from cmd layer).
func RemovePIDFile(fs afero.Fs, baseDir string) {
	removePIDFile(fs, baseDir)
}

// IsProxyRunning checks if a proxy process is already running by reading the
// PID file and checking process liveness (T-09-05 stale PID detection).
func IsProxyRunning(fs afero.Fs, baseDir string) (bool, int) {
	pidPath := filepath.Join(baseDir, proxySubDir, pidFileName)
	data, err := afero.ReadFile(fs, pidPath)
	if err != nil {
		return false, 0
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return false, 0
	}

	// Check if process is alive by sending signal 0.
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false, pid
	}
	if err := proc.Signal(syscall.Signal(0)); err != nil {
		// Process not running -- stale PID file.
		return false, pid
	}

	return true, pid
}
