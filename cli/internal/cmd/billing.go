package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"github.com/skillledger/skillledger/internal/credentials"
)

// lipgloss styles for billing command output.
var (
	billingSuccessStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("2")).Bold(true)
	billingInfoStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("6"))
)

// billingURLResponse is the JSON shape returned by billing checkout/portal endpoints.
type billingURLResponse struct {
	URL string `json:"url"`
}

// openBrowser attempts to open the given URL in the user's default browser.
func openBrowser(url string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", url).Start()
	case "linux":
		return exec.Command("xdg-open", url).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	default:
		return fmt.Errorf("unsupported platform")
	}
}

var billingCmd = &cobra.Command{
	Use:   "billing",
	Short: "Manage billing and subscription",
	Long:  "Upgrade to pay-as-you-go billing or manage your subscription via Stripe.",
}

var billingUpgradeCmd = &cobra.Command{
	Use:   "upgrade",
	Short: "Open Stripe Checkout to add payment method",
	RunE: func(cmd *cobra.Command, args []string) error {
		serviceURL := resolveServiceURL(cmd, "service-url")
		creds, err := credentials.EnsureFresh(serviceURL)
		if err != nil {
			return fmt.Errorf("not logged in — run 'skillledger login' first: %w", err)
		}

		req, err := http.NewRequest("POST", serviceURL+"/v1/billing/checkout", nil)
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
			return fmt.Errorf("checkout failed (status %d): %s", resp.StatusCode, string(respBody))
		}

		var result billingURLResponse
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return fmt.Errorf("decoding response: %w", err)
		}

		fmt.Fprintln(os.Stdout)
		if err := openBrowser(result.URL); err != nil {
			// Browser unavailable -- print URL instead
			fmt.Fprintf(os.Stdout, "%s\n\n", billingInfoStyle.Render("Open this URL to complete payment:"))
			fmt.Fprintf(os.Stdout, "  %s\n\n", result.URL)
		} else {
			fmt.Fprintf(os.Stdout, "%s\n\n", billingSuccessStyle.Render("Opening Stripe Checkout in your browser..."))
		}
		return nil
	},
}

var billingPortalCmd = &cobra.Command{
	Use:   "portal",
	Short: "Open Stripe Customer Portal to manage subscription",
	RunE: func(cmd *cobra.Command, args []string) error {
		serviceURL := resolveServiceURL(cmd, "service-url")
		creds, err := credentials.EnsureFresh(serviceURL)
		if err != nil {
			return fmt.Errorf("not logged in — run 'skillledger login' first: %w", err)
		}

		req, err := http.NewRequest("POST", serviceURL+"/v1/billing/portal", nil)
		if err != nil {
			return fmt.Errorf("creating request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+creds.AccessToken)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("request failed: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusBadRequest {
			return fmt.Errorf("no billing account found. Run 'skillledger billing upgrade' first")
		}
		if resp.StatusCode != http.StatusOK {
			respBody, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("portal request failed (status %d): %s", resp.StatusCode, string(respBody))
		}

		var result billingURLResponse
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return fmt.Errorf("decoding response: %w", err)
		}

		fmt.Fprintln(os.Stdout)
		if err := openBrowser(result.URL); err != nil {
			fmt.Fprintf(os.Stdout, "%s\n\n", billingInfoStyle.Render("Open this URL to manage billing:"))
			fmt.Fprintf(os.Stdout, "  %s\n\n", result.URL)
		} else {
			fmt.Fprintf(os.Stdout, "%s\n\n", billingSuccessStyle.Render("Opening Stripe Customer Portal in your browser..."))
		}
		return nil
	},
}

func init() {
	billingUpgradeCmd.Flags().String("service-url", defaultServiceURL, "SkillLedger service URL")
	billingPortalCmd.Flags().String("service-url", defaultServiceURL, "SkillLedger service URL")
	billingCmd.AddCommand(billingUpgradeCmd, billingPortalCmd)
	rootCmd.AddCommand(billingCmd)
}
