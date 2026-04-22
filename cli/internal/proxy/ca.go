package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"path/filepath"
	"time"

	"github.com/spf13/afero"
)

const (
	caDirName  = "proxy-ca"
	caCertFile = "ca.crt"
	caKeyFile  = "ca.key"
)

// GenerateCA creates a new ECDSA P-256 CA certificate for MITM interception.
func GenerateCA() (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ECDSA key: %w", err)
	}

	// Generate a random 128-bit serial number per RFC 5280 Section 4.1.2.2.
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"SkillLedger Proxy CA"},
			CommonName:   "SkillLedger Local CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}, nil
}

// LoadOrCreateCA loads an existing CA from disk or generates a new one.
// The CA is stored in baseDir/proxy-ca/ with the certificate at ca.crt
// and the private key at ca.key (0600 permissions per T-09-03).
func LoadOrCreateCA(fs afero.Fs, baseDir string) (*tls.Certificate, error) {
	caDir := filepath.Join(baseDir, caDirName)
	certPath := filepath.Join(caDir, caCertFile)
	keyPath := filepath.Join(caDir, caKeyFile)

	// Try loading existing CA.
	certPEM, certErr := afero.ReadFile(fs, certPath)
	keyPEM, keyErr := afero.ReadFile(fs, keyPath)

	if certErr == nil && keyErr == nil {
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err == nil {
			return &cert, nil
		}
		// Fall through to regeneration if existing files are corrupted.
	}

	// Generate new CA.
	ca, err := GenerateCA()
	if err != nil {
		return nil, fmt.Errorf("generate CA: %w", err)
	}

	// Persist to disk.
	if err := fs.MkdirAll(caDir, 0700); err != nil {
		return nil, fmt.Errorf("create CA directory: %w", err)
	}

	// Encode certificate PEM.
	certPEMBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.Certificate[0],
	})
	if err := afero.WriteFile(fs, certPath, certPEMBlock, 0644); err != nil {
		return nil, fmt.Errorf("write CA certificate: %w", err)
	}

	// Encode private key PEM.
	keyDER, err := x509.MarshalECPrivateKey(ca.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("marshal EC private key: %w", err)
	}
	keyPEMBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	})
	if err := afero.WriteFile(fs, keyPath, keyPEMBlock, 0600); err != nil {
		return nil, fmt.Errorf("write CA key: %w", err)
	}

	return ca, nil
}

// CADir returns the CA directory path under baseDir.
func CADir(baseDir string) string {
	return filepath.Join(baseDir, caDirName)
}

// CACertPath returns the CA certificate file path under baseDir.
func CACertPath(baseDir string) string {
	return filepath.Join(baseDir, caDirName, caCertFile)
}
