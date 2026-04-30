package cmd

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"github.com/skillledger/skillledger/internal/credentials"
)

// lipgloss styles for login command output.
var (
	loginSuccessStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("2")).Bold(true)
	loginInfoStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("6"))
	loginErrorStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("1"))
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with SkillLedger using email OTP",
	Long:  "Log in to SkillLedger by entering your email and a verification code sent to your inbox.",
	RunE:  runLogin,
}

// loginTokenResponse is the JSON shape returned by POST /v1/auth/verify.
type loginTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
}

func runLogin(cmd *cobra.Command, args []string) error {
	serviceURL := resolveServiceURL(cmd, "service-url")
	reader := bufio.NewReader(os.Stdin)

	// Step 1: Prompt for email
	fmt.Fprint(os.Stdout, loginInfoStyle.Render("Email: "))
	emailLine, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("reading email: %w", err)
	}
	email := strings.TrimSpace(emailLine)
	if email == "" {
		return fmt.Errorf("email is required")
	}

	// Step 2: Request OTP
	if err := requestOTP(serviceURL, email); err != nil {
		return fmt.Errorf("requesting verification code: %w", err)
	}
	fmt.Fprintln(os.Stdout, loginInfoStyle.Render("Check your email for a verification code..."))

	// Step 3: Verification loop (max 3 attempts)
	const maxAttempts = 3
	for attempt := 0; attempt < maxAttempts; attempt++ {
		fmt.Fprint(os.Stdout, loginInfoStyle.Render("Verification code: "))
		codeLine, readErr := reader.ReadString('\n')
		if readErr != nil {
			return fmt.Errorf("reading verification code: %w", readErr)
		}
		code := strings.TrimSpace(codeLine)

		// Empty input resends OTP (per D-13)
		if code == "" {
			fmt.Fprintln(os.Stdout, loginInfoStyle.Render("Resending verification code..."))
			if resendErr := requestOTP(serviceURL, email); resendErr != nil {
				fmt.Fprintln(os.Stderr, loginErrorStyle.Render(fmt.Sprintf("Resend failed: %v", resendErr)))
			}
			continue
		}

		// Verify the OTP code
		tokenResp, verifyErr := verifyOTP(serviceURL, email, code)
		if verifyErr != nil {
			fmt.Fprintln(os.Stderr, loginErrorStyle.Render(fmt.Sprintf("Verification failed: %v", verifyErr)))
			continue
		}

		// Success: save credentials
		creds := &credentials.Credentials{
			AccessToken:  tokenResp.AccessToken,
			RefreshToken: tokenResp.RefreshToken,
			ExpiresAt:    credentials.ExtractExpiry(tokenResp.AccessToken),
		}
		if saveErr := credentials.Save(creds); saveErr != nil {
			return fmt.Errorf("saving credentials: %w", saveErr)
		}

		fmt.Fprintln(os.Stdout, loginSuccessStyle.Render("Logged in successfully!"))
		return nil
	}

	return fmt.Errorf("Too many attempts. Try again in 15 minutes.")
}

// requestOTP sends an OTP request to the auth service.
func requestOTP(serviceURL, email string) error {
	body, err := json.Marshal(map[string]string{"email": email})
	if err != nil {
		return fmt.Errorf("marshaling request: %w", err)
	}

	resp, err := http.Post(serviceURL+"/v1/auth/register", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return fmt.Errorf("rate limited: please wait before requesting another code")
	}
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server error (status %d): %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// verifyOTP exchanges an email and OTP code for access and refresh tokens.
func verifyOTP(serviceURL, email, code string) (*loginTokenResponse, error) {
	body, err := json.Marshal(map[string]string{"email": email, "code": code})
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	resp, err := http.Post(serviceURL+"/v1/auth/verify", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("verification failed (status %d): %s", resp.StatusCode, string(respBody))
	}

	var tokenResp loginTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return &tokenResp, nil
}

func init() {
	loginCmd.Flags().String("service-url", defaultServiceURL, "SkillLedger service URL")
	rootCmd.AddCommand(loginCmd)
}
