package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"text/tabwriter"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"github.com/skillledger/skillledger/internal/credentials"
)

// lipgloss styles for token command output.
var (
	tokenSuccessStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("2")).Bold(true)
	tokenInfoStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("6"))
	tokenWarnStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("3")).Bold(true)
)

// tokenCreateResponse is the JSON shape returned by POST /v1/auth/tokens.
type tokenCreateResponse struct {
	RawKey    string `json:"raw_key"`
	Name      string `json:"name"`
	KeyPrefix string `json:"key_prefix"`
	ExpiresAt string `json:"expires_at"`
}

// tokenListEntry is a single entry in the GET /v1/auth/tokens response.
type tokenListEntry struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	KeyPrefix string `json:"key_prefix"`
	ExpiresAt string `json:"expires_at"`
	Revoked   bool   `json:"revoked"`
	CreatedAt string `json:"created_at"`
}

var tokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Manage CI/CD API tokens",
	Long:  "Create, list, and revoke long-lived API tokens for CI/CD pipelines.",
}

var tokenCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new CI API token",
	RunE: func(cmd *cobra.Command, args []string) error {
		serviceURL := resolveServiceURL(cmd, "service-url")
		name, _ := cmd.Flags().GetString("name")

		creds, err := credentials.EnsureFresh(serviceURL)
		if err != nil {
			return fmt.Errorf("not logged in: %w", err)
		}

		// POST /v1/auth/tokens with Bearer access_token
		body, err := json.Marshal(map[string]string{"name": name})
		if err != nil {
			return fmt.Errorf("marshaling request: %w", err)
		}

		req, err := http.NewRequest("POST", serviceURL+"/v1/auth/tokens", bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("creating request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+creds.AccessToken)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("request failed: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusCreated {
			respBody, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("token creation failed (status %d): %s", resp.StatusCode, string(respBody))
		}

		var result tokenCreateResponse
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return fmt.Errorf("decoding response: %w", err)
		}

		fmt.Fprintln(os.Stdout)
		fmt.Fprintln(os.Stdout, tokenSuccessStyle.Render("Token created successfully"))
		fmt.Fprintf(os.Stdout, "\n  %s  %s\n", tokenInfoStyle.Render("Name:"), result.Name)
		fmt.Fprintf(os.Stdout, "  %s  %s\n", tokenInfoStyle.Render("Prefix:"), result.KeyPrefix)
		fmt.Fprintf(os.Stdout, "  %s  %s\n", tokenInfoStyle.Render("Expires:"), result.ExpiresAt)
		fmt.Fprintf(os.Stdout, "\n  %s  %s\n\n", tokenInfoStyle.Render("Token:"), result.RawKey)
		fmt.Fprintln(os.Stdout, tokenWarnStyle.Render("This token will not be shown again. Store it securely."))
		fmt.Fprintln(os.Stdout)

		return nil
	},
}

var tokenListCmd = &cobra.Command{
	Use:   "list",
	Short: "List your CI API tokens",
	RunE: func(cmd *cobra.Command, args []string) error {
		serviceURL := resolveServiceURL(cmd, "service-url")

		creds, err := credentials.EnsureFresh(serviceURL)
		if err != nil {
			return fmt.Errorf("not logged in: %w", err)
		}

		// GET /v1/auth/tokens with Bearer access_token
		req, err := http.NewRequest("GET", serviceURL+"/v1/auth/tokens", nil)
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
			return fmt.Errorf("listing tokens failed (status %d): %s", resp.StatusCode, string(respBody))
		}

		var tokens []tokenListEntry
		if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
			return fmt.Errorf("decoding response: %w", err)
		}

		if len(tokens) == 0 {
			fmt.Fprintln(os.Stdout, tokenInfoStyle.Render("No tokens found. Create one with 'skillledger token create --name <label>'."))
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tNAME\tPREFIX\tEXPIRES\tREVOKED\tCREATED")
		for _, t := range tokens {
			revoked := "no"
			if t.Revoked {
				revoked = "yes"
			}
			fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\n",
				t.ID, t.Name, t.KeyPrefix, t.ExpiresAt, revoked, t.CreatedAt)
		}
		w.Flush()

		return nil
	},
}

var tokenRevokeCmd = &cobra.Command{
	Use:   "revoke <token-id>",
	Short: "Revoke a CI API token",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		serviceURL := resolveServiceURL(cmd, "service-url")

		tokenID, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("invalid token ID: %w", err)
		}

		creds, err := credentials.EnsureFresh(serviceURL)
		if err != nil {
			return fmt.Errorf("not logged in: %w", err)
		}

		// DELETE /v1/auth/tokens/{id} with Bearer access_token
		req, err := http.NewRequest("DELETE", fmt.Sprintf("%s/v1/auth/tokens/%d", serviceURL, tokenID), nil)
		if err != nil {
			return fmt.Errorf("creating request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+creds.AccessToken)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("request failed: %w", err)
		}
		defer resp.Body.Close()

		switch resp.StatusCode {
		case http.StatusNoContent:
			fmt.Fprintln(os.Stdout, tokenSuccessStyle.Render("Token revoked."))
		case http.StatusNotFound:
			fmt.Fprintln(os.Stdout, "Token not found.")
		default:
			respBody, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("revoke failed (status %d): %s", resp.StatusCode, string(respBody))
		}

		return nil
	},
}

func init() {
	tokenCreateCmd.Flags().String("name", "", "descriptive label for the token (required)")
	tokenCreateCmd.Flags().Bool("ci", false, "create a CI/CD token (1-year expiry)")
	_ = tokenCreateCmd.MarkFlagRequired("name")
	tokenCreateCmd.Flags().String("service-url", defaultServiceURL, "SkillLedger service URL")
	tokenListCmd.Flags().String("service-url", defaultServiceURL, "SkillLedger service URL")
	tokenRevokeCmd.Flags().String("service-url", defaultServiceURL, "SkillLedger service URL")

	tokenCmd.AddCommand(tokenCreateCmd, tokenListCmd, tokenRevokeCmd)
	rootCmd.AddCommand(tokenCmd)
}
