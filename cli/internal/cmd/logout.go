package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/skillledger/skillledger/internal/credentials"
)

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Log out of SkillLedger and delete local credentials",
	Long:  "Remove stored credentials from ~/.skillledger/credentials.json.",
	RunE:  runLogout,
}

func runLogout(cmd *cobra.Command, args []string) error {
	if err := credentials.Delete(); err != nil {
		return fmt.Errorf("logout failed: %w", err)
	}
	fmt.Fprintln(os.Stdout, "Logged out successfully.")
	return nil
}

func init() {
	rootCmd.AddCommand(logoutCmd)
}
