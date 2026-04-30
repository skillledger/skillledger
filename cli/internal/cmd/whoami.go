package cmd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"github.com/skillledger/skillledger/internal/credentials"
)

// lipgloss styles for whoami command output.
var (
	whoamiInfoStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("6"))
	whoamiWarnStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("3"))
)

var whoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Show the currently logged-in user",
	Long:  "Display the email and token expiry for the current SkillLedger session.",
	RunE: func(cmd *cobra.Command, args []string) error {
		creds, err := credentials.Load()
		if err != nil {
			return fmt.Errorf("not logged in (run 'skillledger login' first)")
		}

		// Decode JWT payload (base64, no signature verification)
		email, exp, decodeErr := decodeJWTClaims(creds.AccessToken)
		if decodeErr != nil {
			return fmt.Errorf("invalid token format: %w", decodeErr)
		}

		fmt.Fprintf(os.Stdout, "%s %s\n", whoamiInfoStyle.Render("Logged in as:"), email)
		fmt.Fprintf(os.Stdout, "%s %s\n", whoamiInfoStyle.Render("Token expires:"), time.Unix(exp, 0).Format(time.RFC3339))

		if creds.NeedsRefresh() {
			fmt.Fprintln(os.Stdout, whoamiWarnStyle.Render("Token needs refresh. Run any authenticated command to auto-refresh."))
		}

		return nil
	},
}

// decodeJWTClaims extracts email and exp from a JWT token payload without
// verifying the signature. This is safe for display purposes because the
// server validates the signature on every authenticated request.
func decodeJWTClaims(token string) (email string, exp int64, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", 0, fmt.Errorf("token is not a valid JWT (expected 3 parts, got %d)", len(parts))
	}

	payload, decErr := base64.RawURLEncoding.DecodeString(parts[1])
	if decErr != nil {
		return "", 0, fmt.Errorf("decoding JWT payload: %w", decErr)
	}

	var claims struct {
		Email string `json:"email"`
		Sub   string `json:"sub"`
		Exp   int64  `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", 0, fmt.Errorf("parsing JWT claims: %w", err)
	}

	// Use email claim, fall back to sub claim
	identity := claims.Email
	if identity == "" {
		identity = claims.Sub
	}
	if identity == "" {
		identity = "(unknown)"
	}

	return identity, claims.Exp, nil
}

func init() {
	rootCmd.AddCommand(whoamiCmd)
}
