package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"

	"github.com/skillledger/skillledger/internal/proxy"
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
	port, _ := cmd.Flags().GetInt("port")
	logSize, _ := cmd.Flags().GetInt("decision-log-size")
	baseDir := proxyBaseDir()

	// Check if proxy is already running.
	running, pid := proxy.IsProxyRunning(afero.NewOsFs(), baseDir)
	if running {
		return fmt.Errorf("proxy already running (PID %d)", pid)
	}

	server := proxy.NewProxyServer(
		proxy.WithPort(port),
		proxy.WithBaseDir(baseDir),
		proxy.WithDecisionLogSize(logSize),
		proxy.WithLogger(log.Logger),
	)

	log.Info().Int("port", port).Msgf("Starting proxy on 127.0.0.1:%d", port)
	log.Info().Str("ca_cert", proxy.CACertPath(baseDir)).Msg("CA certificate location")
	log.Info().Msg("Run `skillledger proxy trust` to install CA into system trust store")

	// Handle SIGTERM/SIGINT for graceful shutdown.
	ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	return server.Start(ctx)
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
}
