package proxy

import (
	"fmt"
	"os/exec"
	"runtime"
)

// InstallCATrust installs the SkillLedger proxy CA certificate into the system
// trust store. This enables HTTPS interception without certificate warnings.
//
// On macOS, it uses the security command to add the cert to the System keychain.
// On Linux, it copies the cert to ca-certificates and runs update-ca-certificates.
//
// This intentionally does NOT use afero.Fs because it shells out to OS commands
// that operate on the real filesystem. This is the one exception to the afero rule.
//
// WARNING: This requires elevated privileges (sudo on Linux, admin on macOS).
// Per T-09-08: never auto-install; only runs via explicit `proxy trust` command.
func InstallCATrust(certPath string) error {
	switch runtime.GOOS {
	case "darwin":
		cmd := exec.Command("security", "add-trusted-cert",
			"-d",
			"-r", "trustRoot",
			"-k", "/Library/Keychains/System.keychain",
			certPath,
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("install CA cert to macOS keychain: %w\noutput: %s", err, out)
		}
		return nil

	case "linux":
		// Copy cert to ca-certificates directory.
		cpCmd := exec.Command("sudo", "cp", certPath, "/usr/local/share/ca-certificates/skillledger-proxy.crt")
		if out, err := cpCmd.CombinedOutput(); err != nil {
			return fmt.Errorf("copy CA cert to ca-certificates: %w\noutput: %s", err, out)
		}

		// Update the system certificate store.
		updateCmd := exec.Command("sudo", "update-ca-certificates")
		if out, err := updateCmd.CombinedOutput(); err != nil {
			return fmt.Errorf("update-ca-certificates: %w\noutput: %s", err, out)
		}
		return nil

	default:
		return fmt.Errorf("unsupported OS for trust store installation: %s -- manually trust the CA certificate at %s", runtime.GOOS, certPath)
	}
}

// RemoveCATrust removes the SkillLedger proxy CA certificate from the system
// trust store.
//
// On macOS, it uses the security command to remove the trusted cert.
// On Linux, it removes the cert file and refreshes the certificate store.
func RemoveCATrust(certPath string) error {
	switch runtime.GOOS {
	case "darwin":
		cmd := exec.Command("security", "remove-trusted-cert",
			"-d",
			certPath,
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("remove CA cert from macOS keychain: %w\noutput: %s", err, out)
		}
		return nil

	case "linux":
		// Remove the cert file.
		rmCmd := exec.Command("sudo", "rm", "/usr/local/share/ca-certificates/skillledger-proxy.crt")
		if out, err := rmCmd.CombinedOutput(); err != nil {
			return fmt.Errorf("remove CA cert file: %w\noutput: %s", err, out)
		}

		// Refresh the certificate store.
		updateCmd := exec.Command("sudo", "update-ca-certificates", "--fresh")
		if out, err := updateCmd.CombinedOutput(); err != nil {
			return fmt.Errorf("update-ca-certificates --fresh: %w\noutput: %s", err, out)
		}
		return nil

	default:
		return fmt.Errorf("unsupported OS for trust store removal: %s -- manually remove the CA certificate", runtime.GOOS)
	}
}
