package proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/elazarl/goproxy"
	"github.com/rs/zerolog"
	"github.com/spf13/afero"
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
	fs          afero.Fs
	baseDir     string
	port        int
	decisionLog *DecisionLog
	handler     *Handler
	proxy       *goproxy.ProxyHttpServer
	listener    net.Listener
	logger      zerolog.Logger
	logSize     int
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

	s.decisionLog = NewDecisionLog(s.logSize)
	s.handler = NewHandler(s.decisionLog, s.logger)
	s.proxy = goproxy.NewProxyHttpServer()

	return s
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

func (s *ProxyServer) cleanup() {
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
