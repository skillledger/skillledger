// Package credentials manages CLI authentication token storage, auto-refresh,
// and JWT expiry extraction. Credentials are stored in ~/.skillledger/credentials.json
// with restricted file permissions (0600 file, 0700 directory).
package credentials

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Credentials holds the OAuth2-style tokens returned by the auth service.
type Credentials struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    int64  `json:"expires_at"`
}

// tokenResponse is the JSON shape returned by POST /v1/auth/refresh.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
}

// refreshWindow is the number of seconds before expiry at which we consider
// the access token stale and trigger a refresh (5 minutes).
const refreshWindow = 300

// Path returns the filesystem path to the credentials file.
// Default: ~/.skillledger/credentials.json
func Path() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = os.Getenv("HOME")
	}
	return filepath.Join(home, ".skillledger", "credentials.json")
}

// Load reads and parses the credentials file. Returns an error if the file
// does not exist or contains invalid JSON.
func Load() (*Credentials, error) {
	data, err := os.ReadFile(Path())
	if err != nil {
		return nil, fmt.Errorf("loading credentials: %w", err)
	}
	var creds Credentials
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, fmt.Errorf("parsing credentials: %w", err)
	}
	return &creds, nil
}

// Save writes credentials to disk with restricted permissions.
// The parent directory is created with 0700 and the file with 0600.
func Save(creds *Credentials) error {
	p := Path()
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating credentials directory: %w", err)
	}
	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling credentials: %w", err)
	}
	if err := os.WriteFile(p, data, 0600); err != nil {
		return fmt.Errorf("writing credentials: %w", err)
	}
	return nil
}

// Delete removes the credentials file. Returns nil if the file does not exist
// (idempotent delete).
func Delete() error {
	err := os.Remove(Path())
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("deleting credentials: %w", err)
	}
	return nil
}

// NeedsRefresh returns true when the access token is within 5 minutes of
// expiry or already expired.
func (c *Credentials) NeedsRefresh() bool {
	return time.Now().Unix() >= c.ExpiresAt-refreshWindow
}

// ExtractExpiry parses the exp claim from a JWT token without verifying the
// signature. This is safe for the CLI because the server validates the
// signature; the CLI only needs the expiry for refresh timing.
func ExtractExpiry(token string) int64 {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return 0
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return 0
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return 0
	}
	return claims.Exp
}

// Refresh exchanges a refresh token for a new token pair by calling
// POST /v1/auth/refresh on the service.
func Refresh(serviceURL string, refreshToken string) (*Credentials, error) {
	body, err := json.Marshal(map[string]string{
		"refresh_token": refreshToken,
	})
	if err != nil {
		return nil, fmt.Errorf("marshaling refresh request: %w", err)
	}

	resp, err := http.Post(serviceURL+"/v1/auth/refresh", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("refresh request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("refresh failed (status %d): %s", resp.StatusCode, string(respBody))
	}

	var tokenResp tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("decoding refresh response: %w", err)
	}

	creds := &Credentials{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		ExpiresAt:    ExtractExpiry(tokenResp.AccessToken),
	}
	return creds, nil
}

// EnsureFresh loads credentials and automatically refreshes them if the access
// token is near expiry. Updated credentials are saved back to disk.
func EnsureFresh(serviceURL string) (*Credentials, error) {
	creds, err := Load()
	if err != nil {
		return nil, fmt.Errorf("not logged in: %w", err)
	}

	if !creds.NeedsRefresh() {
		return creds, nil
	}

	newCreds, err := Refresh(serviceURL, creds.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("token refresh failed: %w", err)
	}

	if err := Save(newCreds); err != nil {
		return nil, fmt.Errorf("saving refreshed credentials: %w", err)
	}

	return newCreds, nil
}
