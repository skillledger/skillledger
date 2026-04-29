package ml

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"

	"github.com/rs/zerolog/log"
)

const (
	modelVersion      = "v2"
	modelRepoURL      = "https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2/resolve/main"
	modelFileName     = "model.onnx"
	tokenizerFileName = "tokenizer.json"

	// ORT version to download (matches yalue/onnxruntime_go target).
	ortVersion = "v1.20.1"
	ortBaseURL = "https://github.com/nicenemo/onnxruntime-static-lib/releases/download/" + ortVersion
)

// ModelStatus reports the current state of the ML model on disk.
type ModelStatus struct {
	Downloaded    bool   `json:"downloaded"`
	ModelPath     string `json:"model_path,omitempty"`
	TokenizerPath string `json:"tokenizer_path,omitempty"`
	OrtLibPath    string `json:"ort_lib_path,omitempty"`
	ModelSize     int64  `json:"model_size_bytes,omitempty"`
	Version       string `json:"version"`
	Platform      string `json:"platform"`
	Verified      bool   `json:"verified"`
}

// pinnedChecksums contains SHA-256 checksums for each downloaded file.
// Update these when upgrading to a new model version.
// TODO(CR-03): These are placeholder hashes. Replace with actual SHA-256 checksums
// computed from a verified download of protectai/deberta-v3-base-prompt-injection-v2.
// Until real hashes are populated, VerifyChecksum() will fail-closed (reject unverified models).
var pinnedChecksums = map[string]string{
	// Placeholder checksums — VerifyChecksum fails-closed when hash is "PLACEHOLDER".
	modelFileName:     "PLACEHOLDER",
	tokenizerFileName: "PLACEHOLDER",
}

// ortPlatform describes a platform-specific ONNX Runtime shared library.
type ortPlatform struct {
	URL      string
	FileName string
	SHA256   string
}

// ortPlatformMap maps GOOS-GOARCH keys to ORT shared library info.
var ortPlatformMap = map[string]ortPlatform{
	"darwin-arm64": {
		URL:      "https://github.com/yalue/onnxruntime_go/releases/download/v1.20.1/onnxruntime_arm64.dylib",
		FileName: "libonnxruntime.dylib",
	},
	"darwin-amd64": {
		URL:      "https://github.com/yalue/onnxruntime_go/releases/download/v1.20.1/onnxruntime_amd64.dylib",
		FileName: "libonnxruntime.dylib",
	},
	"linux-amd64": {
		URL:      "https://github.com/yalue/onnxruntime_go/releases/download/v1.20.1/onnxruntime.so",
		FileName: "libonnxruntime.so",
	},
	"linux-arm64": {
		URL:      "https://github.com/yalue/onnxruntime_go/releases/download/v1.20.1/onnxruntime_arm64.so",
		FileName: "libonnxruntime.so",
	},
}

// ortPlatformInfo returns the ORT shared library info for the current platform.
func ortPlatformInfo() (*ortPlatform, error) {
	key := runtime.GOOS + "-" + runtime.GOARCH
	info, ok := ortPlatformMap[key]
	if !ok {
		return nil, fmt.Errorf("unsupported platform for ONNX Runtime: %s", key)
	}
	return &info, nil
}

// ortLibFileName returns the ORT shared library filename for the current platform.
func ortLibFileName() string {
	info, err := ortPlatformInfo()
	if err != nil {
		// Fallback for unsupported platforms.
		return "libonnxruntime.so"
	}
	return info.FileName
}

// ModelManager handles downloading, caching, and verifying ML model files.
// It manages the model directory at ~/.skillledger/models/<model-name>/.
type ModelManager struct {
	baseDir string
	client  *http.Client
}

// NewModelManager creates a new ModelManager rooted at baseDir (typically ~/.skillledger).
func NewModelManager(baseDir string) *ModelManager {
	return &ModelManager{
		baseDir: baseDir,
		client:  &http.Client{},
	}
}

// ModelDir returns the directory containing model files.
func (m *ModelManager) ModelDir() string {
	return filepath.Join(m.baseDir, "models", DefaultModelName)
}

// ModelPath returns the full path to the ONNX model file.
func (m *ModelManager) ModelPath() string {
	return filepath.Join(m.ModelDir(), modelFileName)
}

// TokenizerPath returns the full path to the tokenizer.json file.
func (m *ModelManager) TokenizerPath() string {
	return filepath.Join(m.ModelDir(), tokenizerFileName)
}

// OrtLibPath returns the full path to the ORT shared library for the current platform.
func (m *ModelManager) OrtLibPath() string {
	return filepath.Join(m.ModelDir(), ortLibFileName())
}

// IsDownloaded returns true when all three required files exist on disk:
// model.onnx, tokenizer.json, and the platform ORT shared library.
func (m *ModelManager) IsDownloaded() bool {
	for _, path := range []string{m.ModelPath(), m.TokenizerPath(), m.OrtLibPath()} {
		if _, err := os.Stat(path); err != nil {
			return false
		}
	}
	return true
}

// EnsureModelDir creates the model directory with 0700 permissions if it doesn't exist.
func (m *ModelManager) EnsureModelDir() error {
	dir := m.ModelDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create model directory: %w", err)
	}
	// Ensure the final directory has correct permissions (MkdirAll may not set them on existing dirs).
	if err := os.Chmod(dir, 0700); err != nil {
		return fmt.Errorf("set model directory permissions: %w", err)
	}
	return nil
}

// Download fetches the model files (model.onnx, tokenizer.json, ORT shared lib)
// from their respective URLs. Files that already exist with correct checksums
// are not re-downloaded (idempotent).
//
// progressFn is an optional callback receiving (filename, bytesDownloaded, totalBytes).
// Pass nil to disable progress reporting.
func (m *ModelManager) Download(ctx context.Context, progressFn func(file string, downloaded, total int64)) error {
	if err := m.EnsureModelDir(); err != nil {
		return err
	}

	ortInfo, err := ortPlatformInfo()
	if err != nil {
		return err
	}

	downloads := []struct {
		url      string
		filename string
		destPath string
	}{
		{
			url:      modelRepoURL + "/" + modelFileName,
			filename: modelFileName,
			destPath: m.ModelPath(),
		},
		{
			url:      modelRepoURL + "/" + tokenizerFileName,
			filename: tokenizerFileName,
			destPath: m.TokenizerPath(),
		},
		{
			url:      ortInfo.URL,
			filename: ortInfo.FileName,
			destPath: m.OrtLibPath(),
		},
	}

	for _, dl := range downloads {
		// Check if file already exists with correct checksum.
		if m.fileVerified(dl.filename, dl.destPath) {
			log.Debug().Str("file", dl.filename).Msg("file already downloaded and verified, skipping")
			if progressFn != nil {
				fi, _ := os.Stat(dl.destPath)
				if fi != nil {
					progressFn(dl.filename, fi.Size(), fi.Size())
				}
			}
			continue
		}

		if err := m.downloadFile(ctx, dl.url, dl.destPath, dl.filename, progressFn); err != nil {
			return fmt.Errorf("download %s: %w", dl.filename, err)
		}
	}

	return nil
}

// downloadFile fetches a single file from url to destPath with atomic rename.
func (m *ModelManager) downloadFile(ctx context.Context, url, destPath, filename string, progressFn func(string, int64, int64)) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}

	// Create temp file in the same directory (for atomic rename).
	dir := filepath.Dir(destPath)
	tmpFile, err := os.CreateTemp(dir, ".download-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer func() {
		tmpFile.Close()
		os.Remove(tmpPath) // Clean up on error; no-op if renamed.
	}()

	// Download with SHA-256 computation via TeeReader.
	hasher := sha256.New()
	var downloaded int64
	total := resp.ContentLength

	reader := io.TeeReader(resp.Body, hasher)

	buf := make([]byte, 32*1024)
	for {
		n, readErr := reader.Read(buf)
		if n > 0 {
			if _, writeErr := tmpFile.Write(buf[:n]); writeErr != nil {
				return fmt.Errorf("write temp file: %w", writeErr)
			}
			downloaded += int64(n)
			if progressFn != nil {
				progressFn(filename, downloaded, total)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("read response body: %w", readErr)
		}
	}

	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}

	// Verify checksum if we have a pinned value.
	computedHash := hex.EncodeToString(hasher.Sum(nil))
	if expected, ok := pinnedChecksums[filename]; ok && expected != "" {
		if computedHash != expected {
			return fmt.Errorf("checksum mismatch for %s: expected %s, got %s", filename, expected, computedHash)
		}
	} else {
		log.Warn().Str("file", filename).Str("sha256", computedHash).Msg("no pinned checksum for file; recording computed hash")
	}

	// Atomic rename.
	if err := os.Rename(tmpPath, destPath); err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}

	return nil
}

// fileVerified checks if a file exists and has the correct pinned checksum.
func (m *ModelManager) fileVerified(filename, path string) bool {
	expected, ok := pinnedChecksums[filename]
	if !ok || expected == "" {
		// No pinned checksum: can't verify, treat as not verified.
		return false
	}

	hash, err := fileSHA256(path)
	if err != nil {
		return false
	}

	return hash == expected
}

// Verify checks SHA-256 of each downloaded file against pinned checksums.
// Returns the first mismatch as an error. Fail-closed: if no pinned checksum
// exists for a required file, verification fails (CR-03: prevent unverified models).
func (m *ModelManager) Verify() error {
	files := map[string]string{
		modelFileName:     m.ModelPath(),
		tokenizerFileName: m.TokenizerPath(),
		ortLibFileName():  m.OrtLibPath(),
	}

	for name, path := range files {
		expected, ok := pinnedChecksums[name]
		if !ok || expected == "" || expected == "PLACEHOLDER" {
			// Fail-closed: no valid pinned hash means verification fails (CR-03).
			return fmt.Errorf("no valid pinned checksum for %s (fail-closed); populate pinnedChecksums with real SHA-256 hashes", name)
		}

		actual, err := fileSHA256(path)
		if err != nil {
			return fmt.Errorf("verify %s: %w", name, err)
		}

		if actual != expected {
			return fmt.Errorf("checksum mismatch for %s: expected %s, got %s", name, expected, actual)
		}
	}

	return nil
}

// Info returns the current model status.
func (m *ModelManager) Info() (*ModelStatus, error) {
	status := &ModelStatus{
		Version:  modelVersion,
		Platform: runtime.GOOS + "-" + runtime.GOARCH,
	}

	if m.IsDownloaded() {
		status.Downloaded = true
		status.ModelPath = m.ModelPath()
		status.TokenizerPath = m.TokenizerPath()
		status.OrtLibPath = m.OrtLibPath()

		if fi, err := os.Stat(m.ModelPath()); err == nil {
			status.ModelSize = fi.Size()
		}

		// Check verification status.
		if len(pinnedChecksums) > 0 {
			status.Verified = m.Verify() == nil
		}
	}

	return status, nil
}

// ToModelInfo converts the model manager state to a ModelInfo for classifier construction.
func (m *ModelManager) ToModelInfo() *ModelInfo {
	return &ModelInfo{
		Name:          DefaultModelName,
		Version:       modelVersion,
		ModelPath:     m.ModelPath(),
		TokenizerPath: m.TokenizerPath(),
		OrtLibPath:    m.OrtLibPath(),
	}
}

// fileSHA256 computes the SHA-256 hex digest of a file.
func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}
