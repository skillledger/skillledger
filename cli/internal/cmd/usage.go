package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"github.com/skillledger/skillledger/internal/credentials"
)

// lipgloss styles for usage command output.
var (
	usageTitleStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("6")).Bold(true)
	usageLabelStyle = lipgloss.NewStyle().Faint(true)
	usageValueStyle = lipgloss.NewStyle().Bold(true)
	usageWarnStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("3")).Bold(true)
	usageInfoStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("6"))
)

// usageResponse is the JSON shape returned by GET /v1/usage.
type usageResponse struct {
	Operation     string `json:"operation"`
	Used          int    `json:"used"`
	Limit         *int   `json:"limit"`          // nil for paid users
	ResetsAt      string `json:"resets_at"`
	BillingStatus string `json:"billing_status"` // "free", "active", "past_due", "canceled"
}

var usageCmd = &cobra.Command{
	Use:   "usage",
	Short: "Show current month's tlog usage and billing status",
	RunE: func(cmd *cobra.Command, args []string) error {
		serviceURL := resolveServiceURL(cmd, "service-url")
		creds, err := credentials.EnsureFresh(serviceURL)
		if err != nil {
			return fmt.Errorf("not logged in — run 'skillledger login' first: %w", err)
		}

		req, err := http.NewRequest("GET", serviceURL+"/v1/usage", nil)
		if err != nil {
			return fmt.Errorf("creating request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+creds.AccessToken)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("request failed: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			respBody, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("usage query failed (status %d): %s", resp.StatusCode, string(respBody))
		}

		var usage usageResponse
		if err := json.NewDecoder(resp.Body).Decode(&usage); err != nil {
			return fmt.Errorf("decoding response: %w", err)
		}

		// Format output per D-12
		now := time.Now()
		monthLabel := now.Format("January 2006")
		fmt.Fprintf(os.Stdout, "\n%s\n\n", usageTitleStyle.Render("SkillLedger Usage ("+monthLabel+")"))

		if usage.BillingStatus == "free" && usage.Limit != nil {
			fmt.Fprintf(os.Stdout, "  %-18s %d / %d (free tier)\n", usageLabelStyle.Render("Tlog publishes:"), usage.Used, *usage.Limit)
			fmt.Fprintf(os.Stdout, "  %-18s %s\n", usageLabelStyle.Render("Status:"), "Free")
			fmt.Fprintf(os.Stdout, "\n  %s\n\n", usageInfoStyle.Render("Upgrade: skillledger billing upgrade"))
		} else if usage.BillingStatus == "active" {
			fmt.Fprintf(os.Stdout, "  %-18s %d\n", usageLabelStyle.Render("Tlog publishes:"), usage.Used)
			fmt.Fprintf(os.Stdout, "  %-18s %s\n", usageLabelStyle.Render("Status:"), usageValueStyle.Render("Active (pay-as-you-go)"))
			fmt.Fprintf(os.Stdout, "\n  %s\n\n", usageInfoStyle.Render("Billing portal: skillledger billing portal"))
		} else {
			// past_due or canceled
			limitStr := fmt.Sprintf("%d", usage.Used)
			if usage.Limit != nil {
				limitStr = fmt.Sprintf("%d / %d", usage.Used, *usage.Limit)
			}
			fmt.Fprintf(os.Stdout, "  %-18s %s\n", usageLabelStyle.Render("Tlog publishes:"), limitStr)
			fmt.Fprintf(os.Stdout, "  %-18s %s\n", usageLabelStyle.Render("Status:"), usageWarnStyle.Render(usage.BillingStatus))
			fmt.Fprintf(os.Stdout, "\n  %s\n\n", usageInfoStyle.Render("Manage billing: skillledger billing portal"))
		}
		return nil
	},
}

func init() {
	usageCmd.Flags().String("service-url", defaultServiceURL, "SkillLedger service URL")
	rootCmd.AddCommand(usageCmd)
}
