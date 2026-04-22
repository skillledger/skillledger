package cmd

import (
	"fmt"
	"os"
	"syscall"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"

	"github.com/skillledger/skillledger/internal/proxy"
)

var proxyStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the running proxy",
	Long:  `Sends SIGTERM to the running SkillLedger proxy process. The proxy shuts down gracefully, cleaning up PID and port files.`,
	RunE:  runProxyStop,
}

func runProxyStop(cmd *cobra.Command, args []string) error {
	baseDir := proxyBaseDir()
	fs := afero.NewOsFs()

	// Read PID from file.
	pid, err := proxy.ReadPIDFile(fs, baseDir)
	if err != nil {
		return fmt.Errorf("proxy is not running")
	}

	// Check if PID is alive (T-09-11: verify before sending signal).
	proc, err := os.FindProcess(pid)
	if err != nil {
		proxy.RemovePIDFile(fs, baseDir)
		return fmt.Errorf("proxy is not running (cleaned stale PID file)")
	}

	// Signal 0 checks liveness without actually sending a signal.
	if err := proc.Signal(syscall.Signal(0)); err != nil {
		proxy.RemovePIDFile(fs, baseDir)
		return fmt.Errorf("proxy is not running (cleaned stale PID file)")
	}

	// Send SIGTERM for graceful shutdown.
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		return fmt.Errorf("failed to send SIGTERM to proxy (PID %d): %w", pid, err)
	}

	log.Info().Int("pid", pid).Msg("Sent SIGTERM to proxy")
	return nil
}
