package cmd

import (
	"os"
	"path/filepath"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/skillledger/skillledger/internal/threatsync"
	"github.com/skillledger/skillledger/internal/updatecheck"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	verbose       bool
	jsonOutput    bool
	noUpdateCheck bool
	updateCheckCh <-chan *updatecheck.Result
	threatSyncer  *threatsync.Syncer
)

// threatCacheDir returns the path to the threat data cache directory.
// Uses $HOME/.skillledger/cache (matching D-01 cache location).
func threatCacheDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = os.Getenv("HOME")
	}
	return filepath.Join(home, ".skillledger", "cache")
}

var rootCmd = &cobra.Command{
	Use:   "skillledger",
	Short: "Build-and-attestation toolchain for AI agent skill artifacts",
	Long: `SkillLedger lets developers build skills from source into content-addressed,
signed artifacts with SLSA-3 provenance, and lets enterprises verify those
artifacts at install time against a transparency log and capability policy.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
		if verbose {
			zerolog.SetGlobalLevel(zerolog.DebugLevel)
		}
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

		// Spawn non-blocking update check (D-14)
		if updatecheck.ShouldCheck(noUpdateCheck) {
			updateCheckCh = updatecheck.CheckAsync(version, afero.NewOsFs(), updatecheck.RegistryURL)
		}

		// Start background threat data sync (D-03)
		serviceURL := defaultServiceURL
		if envURL := os.Getenv("SKILLLEDGER_SERVICE_URL"); envURL != "" {
			serviceURL = envURL
		}
		threatSyncer = threatsync.NewSyncer(serviceURL, threatCacheDir())
		threatSyncer.StartAsync()
	},
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		// Print update notice if available (D-14)
		// Only if stderr is a TTY (D-15: don't pollute machine-readable output)
		if updateCheckCh == nil {
			return
		}
		if !term.IsTerminal(int(os.Stderr.Fd())) {
			return
		}
		// Non-blocking read: if goroutine hasn't finished, skip
		select {
		case result := <-updateCheckCh:
			updatecheck.PrintNotice(result, version)
		default:
			// Check hasn't completed -- drop it, next invocation will retry
		}
	},
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "output as JSON")
	rootCmd.PersistentFlags().BoolVar(&noUpdateCheck, "no-update-check", false, "disable update check")
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}
