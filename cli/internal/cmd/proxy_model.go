package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"github.com/skillledger/skillledger/internal/ml"
)

var modelCmd = &cobra.Command{
	Use:   "model",
	Short: "Manage ML models for prompt injection detection",
	Long: `Commands for managing the DeBERTa ONNX model used by the prompt injection
detection pipeline. The model (~100MB) is downloaded on first use to
~/.skillledger/models/ and verified via SHA-256 checksums.

Use 'skillledger model download' to pre-fetch the model for air-gapped
environments, or 'skillledger model info' to check current status.`,
}

var modelDownloadCmd = &cobra.Command{
	Use:   "download",
	Short: "Download the prompt injection detection model",
	Long: `Downloads the DeBERTa ONNX model, tokenizer, and ONNX Runtime shared library
to ~/.skillledger/models/. Required for ML-based prompt injection detection.
Not needed if built with --no-ml (heuristic-only mode).

Files downloaded:
  - model.onnx       (~100MB) DeBERTa-v3 prompt injection classifier
  - tokenizer.json    (~700KB) HuggingFace tokenizer configuration
  - libonnxruntime.*  (~30MB)  Platform-specific ONNX Runtime shared library

For air-gapped environments, download on a connected machine and copy
~/.skillledger/models/ to the target.`,
	RunE: runModelDownload,
}

var modelInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Show model status and location",
	Long: `Displays the current status of the ML model used for prompt injection detection.
Shows whether the model is downloaded, its version, file paths, sizes, and
verification status.`,
	RunE: runModelInfo,
}

func runModelDownload(cmd *cobra.Command, args []string) error {
	baseDir := proxyBaseDir()
	mm := ml.NewModelManager(baseDir)

	// Check if already downloaded.
	if mm.IsDownloaded() {
		if err := mm.Verify(); err == nil {
			info := mm.ToModelInfo()
			fmt.Printf("Model already downloaded and verified.\n")
			fmt.Printf("  Name:    %s\n", info.Name)
			fmt.Printf("  Version: %s\n", info.Version)
			fmt.Printf("  Path:    %s\n", mm.ModelDir())
			return nil
		}
		// Verification failed -- re-download.
		fmt.Println("Model files exist but verification failed. Re-downloading...")
	}

	info := mm.ToModelInfo()
	fmt.Printf("Downloading prompt injection model: %s (%s)\n", info.Name, info.Version)
	fmt.Println()

	// Set up context with signal handling.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nDownload cancelled.")
		cancel()
	}()

	// Progress callback.
	progressFn := func(file string, downloaded, total int64) {
		if total > 0 {
			pct := float64(downloaded) / float64(total) * 100
			fmt.Printf("\r  %-25s %6.1f MB / %6.1f MB  (%5.1f%%)",
				file,
				float64(downloaded)/1024/1024,
				float64(total)/1024/1024,
				pct)
		} else {
			fmt.Printf("\r  %-25s %6.1f MB",
				file,
				float64(downloaded)/1024/1024)
		}
		if downloaded == total && total > 0 {
			fmt.Println()
		}
	}

	if err := mm.Download(ctx, progressFn); err != nil {
		return fmt.Errorf("download failed: %w", err)
	}

	fmt.Println()

	// Verify after download.
	if err := mm.Verify(); err != nil {
		return fmt.Errorf("post-download verification failed: %w", err)
	}

	status, err := mm.Info()
	if err != nil {
		return err
	}

	fmt.Printf("Download complete.\n")
	fmt.Printf("  Model path:     %s\n", status.ModelPath)
	fmt.Printf("  Tokenizer path: %s\n", status.TokenizerPath)
	fmt.Printf("  ORT lib path:   %s\n", status.OrtLibPath)
	if status.ModelSize > 0 {
		fmt.Printf("  Model size:     %.1f MB\n", float64(status.ModelSize)/1024/1024)
	}

	return nil
}

func runModelInfo(cmd *cobra.Command, args []string) error {
	baseDir := proxyBaseDir()
	mm := ml.NewModelManager(baseDir)

	status, err := mm.Info()
	if err != nil {
		return err
	}

	// Styling.
	headerStyle := lipgloss.NewStyle().Bold(true)
	labelStyle := lipgloss.NewStyle().Width(18).Align(lipgloss.Left)
	successStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("2")) // green
	warnStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("3"))   // yellow

	fmt.Println(headerStyle.Render("Prompt Injection Model Status"))
	fmt.Println()

	// Downloaded status.
	downloadedVal := warnStyle.Render("No")
	if status.Downloaded {
		downloadedVal = successStyle.Render("Yes")
	}
	fmt.Printf("  %s %s\n", labelStyle.Render("Downloaded:"), downloadedVal)

	// Version and platform.
	fmt.Printf("  %s %s\n", labelStyle.Render("Version:"), status.Version)
	fmt.Printf("  %s %s\n", labelStyle.Render("Platform:"), status.Platform)

	if status.Downloaded {
		fmt.Printf("  %s %s\n", labelStyle.Render("Model path:"), status.ModelPath)
		fmt.Printf("  %s %s\n", labelStyle.Render("Tokenizer path:"), status.TokenizerPath)
		fmt.Printf("  %s %s\n", labelStyle.Render("ORT lib path:"), status.OrtLibPath)

		if status.ModelSize > 0 {
			fmt.Printf("  %s %.1f MB\n", labelStyle.Render("Model size:"), float64(status.ModelSize)/1024/1024)
		}

		// Verified status.
		verifiedVal := warnStyle.Render("No (no pinned checksums)")
		if status.Verified {
			verifiedVal = successStyle.Render("Yes")
		}
		fmt.Printf("  %s %s\n", labelStyle.Render("Verified:"), verifiedVal)
	} else {
		fmt.Println()
		fmt.Println(warnStyle.Render("  Run 'skillledger model download' to fetch the model."))
	}

	return nil
}

func init() {
	modelCmd.AddCommand(modelDownloadCmd)
	modelCmd.AddCommand(modelInfoCmd)
	rootCmd.AddCommand(modelCmd)
}
