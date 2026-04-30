package credentials

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

// setHomeDir overrides HOME (and UserHomeDir) to a temp directory for testing.
// Returns a cleanup function that restores the original value.
func setHomeDir(t *testing.T, dir string) {
	t.Helper()
	orig := os.Getenv("HOME")
	t.Setenv("HOME", dir)
	t.Cleanup(func() {
		os.Setenv("HOME", orig)
	})
}

func TestSaveAndLoad(t *testing.T) {
	tmp := t.TempDir()
	setHomeDir(t, tmp)

	want := &Credentials{
		AccessToken:  "access-abc",
		RefreshToken: "refresh-xyz",
		ExpiresAt:    1700000000,
	}

	if err := Save(want); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	got, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if got.AccessToken != want.AccessToken {
		t.Errorf("AccessToken = %q, want %q", got.AccessToken, want.AccessToken)
	}
	if got.RefreshToken != want.RefreshToken {
		t.Errorf("RefreshToken = %q, want %q", got.RefreshToken, want.RefreshToken)
	}
	if got.ExpiresAt != want.ExpiresAt {
		t.Errorf("ExpiresAt = %d, want %d", got.ExpiresAt, want.ExpiresAt)
	}
}

func TestSaveFilePermissions(t *testing.T) {
	tmp := t.TempDir()
	setHomeDir(t, tmp)

	creds := &Credentials{AccessToken: "tok", RefreshToken: "ref", ExpiresAt: 123}
	if err := Save(creds); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	info, err := os.Stat(Path())
	if err != nil {
		t.Fatalf("Stat() error: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("file permissions = %o, want 0600", perm)
	}
}

func TestDeleteCredentials(t *testing.T) {
	tmp := t.TempDir()
	setHomeDir(t, tmp)

	creds := &Credentials{AccessToken: "tok", RefreshToken: "ref", ExpiresAt: 123}
	if err := Save(creds); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	if err := Delete(); err != nil {
		t.Fatalf("Delete() error: %v", err)
	}

	_, err := Load()
	if err == nil {
		t.Error("Load() after Delete() should return error")
	}
}

func TestDeleteNonExistent(t *testing.T) {
	tmp := t.TempDir()
	setHomeDir(t, tmp)

	// File doesn't exist, Delete should return nil (idempotent).
	if err := Delete(); err != nil {
		t.Errorf("Delete() on non-existent file returned error: %v", err)
	}
}

func TestNeedsRefresh_NotExpired(t *testing.T) {
	creds := &Credentials{
		ExpiresAt: time.Now().Unix() + 3600, // 1 hour from now
	}
	if creds.NeedsRefresh() {
		t.Error("NeedsRefresh() = true, want false for token expiring in 1 hour")
	}
}

func TestNeedsRefresh_NearExpiry(t *testing.T) {
	creds := &Credentials{
		ExpiresAt: time.Now().Unix() + 200, // 3m20s from now (< 5 min window)
	}
	if !creds.NeedsRefresh() {
		t.Error("NeedsRefresh() = false, want true for token expiring in < 5 minutes")
	}
}

func TestNeedsRefresh_Expired(t *testing.T) {
	creds := &Credentials{
		ExpiresAt: time.Now().Unix() - 60, // expired 1 minute ago
	}
	if !creds.NeedsRefresh() {
		t.Error("NeedsRefresh() = false, want true for expired token")
	}
}

// makeJWT creates a fake JWT with the given exp claim for testing.
func makeJWT(exp int64) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload, _ := json.Marshal(map[string]int64{"exp": exp})
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	sig := base64.RawURLEncoding.EncodeToString([]byte("fakesig"))
	return fmt.Sprintf("%s.%s.%s", header, payloadB64, sig)
}

func TestExtractExpiry(t *testing.T) {
	exp := int64(1700000000)
	token := makeJWT(exp)
	got := ExtractExpiry(token)
	if got != exp {
		t.Errorf("ExtractExpiry() = %d, want %d", got, exp)
	}
}

func TestExtractExpiry_InvalidToken(t *testing.T) {
	cases := []struct {
		name  string
		token string
	}{
		{"empty string", ""},
		{"no dots", "nodots"},
		{"one dot", "one.dot"},
		{"invalid base64 payload", "a.!!!.c"},
		{"invalid json payload", "a." + base64.RawURLEncoding.EncodeToString([]byte("notjson")) + ".c"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ExtractExpiry(tc.token)
			if got != 0 {
				t.Errorf("ExtractExpiry(%q) = %d, want 0", tc.token, got)
			}
		})
	}
}

func TestRefresh(t *testing.T) {
	exp := time.Now().Unix() + 3600
	accessToken := makeJWT(exp)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/v1/auth/refresh" {
			t.Errorf("path = %s, want /v1/auth/refresh", r.URL.Path)
		}

		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		if body["refresh_token"] != "old-refresh" {
			t.Errorf("refresh_token = %q, want %q", body["refresh_token"], "old-refresh")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tokenResponse{
			AccessToken:  accessToken,
			RefreshToken: "new-refresh",
			TokenType:    "Bearer",
		})
	}))
	defer srv.Close()

	creds, err := Refresh(srv.URL, "old-refresh")
	if err != nil {
		t.Fatalf("Refresh() error: %v", err)
	}
	if creds.AccessToken != accessToken {
		t.Errorf("AccessToken mismatch")
	}
	if creds.RefreshToken != "new-refresh" {
		t.Errorf("RefreshToken = %q, want %q", creds.RefreshToken, "new-refresh")
	}
	if creds.ExpiresAt != exp {
		t.Errorf("ExpiresAt = %d, want %d", creds.ExpiresAt, exp)
	}
}

func TestRefresh_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"detail":"invalid refresh token"}`))
	}))
	defer srv.Close()

	_, err := Refresh(srv.URL, "bad-token")
	if err == nil {
		t.Fatal("Refresh() should return error on 401")
	}
}
