package proxy_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/skillledger/skillledger/internal/proxy"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateCA(t *testing.T) {
	ca, err := proxy.GenerateCA()
	require.NoError(t, err)
	require.NotNil(t, ca)
	require.Len(t, ca.Certificate, 1)

	cert, err := x509.ParseCertificate(ca.Certificate[0])
	require.NoError(t, err)
	assert.True(t, cert.IsCA, "certificate should be a CA")
	assert.Equal(t, "SkillLedger Local CA", cert.Subject.CommonName)

	key, ok := ca.PrivateKey.(*ecdsa.PrivateKey)
	require.True(t, ok, "private key should be ECDSA")
	assert.Equal(t, elliptic.P256(), key.Curve, "key should use P-256 curve")
}

func TestLoadOrCreateCA_GeneratesNew(t *testing.T) {
	fs := afero.NewMemMapFs()
	baseDir := "/test-home/.skillledger"

	ca, err := proxy.LoadOrCreateCA(fs, baseDir)
	require.NoError(t, err)
	require.NotNil(t, ca)

	// Verify files were written to disk.
	certExists, _ := afero.Exists(fs, proxy.CACertPath(baseDir))
	assert.True(t, certExists, "ca.crt should exist")

	caDir := proxy.CADir(baseDir)
	keyPath := caDir + "/ca.key"
	keyExists, _ := afero.Exists(fs, keyPath)
	assert.True(t, keyExists, "ca.key should exist")
}

func TestLoadOrCreateCA_LoadsExisting(t *testing.T) {
	fs := afero.NewMemMapFs()
	baseDir := "/test-home/.skillledger"

	// First call generates.
	ca1, err := proxy.LoadOrCreateCA(fs, baseDir)
	require.NoError(t, err)

	// Second call loads from disk.
	ca2, err := proxy.LoadOrCreateCA(fs, baseDir)
	require.NoError(t, err)

	// Certificate bytes should match.
	assert.Equal(t, ca1.Certificate[0], ca2.Certificate[0],
		"loaded certificate should match generated certificate")
}

func TestLoadOrCreateCA_KeyPermissions(t *testing.T) {
	fs := afero.NewMemMapFs()
	baseDir := "/test-home/.skillledger"

	_, err := proxy.LoadOrCreateCA(fs, baseDir)
	require.NoError(t, err)

	caDir := proxy.CADir(baseDir)
	keyPath := caDir + "/ca.key"
	info, err := fs.Stat(keyPath)
	require.NoError(t, err)
	assert.Equal(t, "-rw-------", info.Mode().String(),
		"ca.key should have 0600 permissions")
}

func TestCACertPath(t *testing.T) {
	path := proxy.CACertPath("/home/user/.skillledger")
	assert.Contains(t, path, "proxy-ca")
	assert.Contains(t, path, "ca.crt")
}

func TestInjectProtocolHeader(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
	proxy.InjectProtocolHeader(r)
	assert.Equal(t, "v1", r.Header.Get("X-SkillLedger-Proxy"))
}

func TestStripProtocolHeader(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
	r.Header.Set("X-SkillLedger-Proxy", "v1")
	proxy.StripProtocolHeader(r)
	assert.Empty(t, r.Header.Get("X-SkillLedger-Proxy"))
}
