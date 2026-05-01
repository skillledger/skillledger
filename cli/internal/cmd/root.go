package cmd

import (
	"os"
	"path/filepath"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/skillledger/skillledger/internal/credentials"
	"github.com/skillledger/skillledger/internal/eventreport"
	"github.com/skillledger/skillledger/internal/orgsync"
	"github.com/skillledger/skillledger/internal/threatsync"
	"github.com/skillledger/skillledger/internal/updatecheck"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	verbose        bool
	jsonOutput     bool
	noUpdateCheck  bool
	updateCheckCh  <-chan *updatecheck.Result
	threatSyncer   *threatsync.Syncer
	orgSyncer      *orgsync.OrgSyncer
	eventReporter  *eventreport.Reporter
	currentOrgSlug string
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

// orgCacheDir returns the path to the org policy cache directory.
// Uses $HOME/.skillledger (org policy cached at ~/.skillledger/org-policy.rego per D-04).
func orgCacheDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = os.Getenv("HOME")
	}
	return filepath.Join(home, ".skillledger")
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

		// Start org policy sync if user belongs to an org (D-12)
		creds, credErr := credentials.Load()
		if credErr == nil && creds.OrgSlug != "" {
			currentOrgSlug = creds.OrgSlug
			orgSyncer = orgsync.NewOrgSyncer(serviceURL, orgCacheDir(), creds.OrgSlug)
			orgSyncer.StartAsync()
			eventReporter = eventreport.NewReporter(serviceURL)
		}
	},
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		// Wait briefly for event reporting to complete (Pitfall 5)
		if eventReporter != nil {
			eventReporter.WaitForReport(2 * time.Second)
		}

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
