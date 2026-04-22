package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"

	"github.com/skillledger/skillledger/internal/proxy"
)

var (
	statusRunningStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("2")) // green
	statusStoppedStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("3")) // yellow
)

var proxyStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show proxy status",
	Long:  `Reports whether the SkillLedger proxy is currently running, including its PID and listening port.`,
	RunE:  runProxyStatus,
}

type proxyStatusJSON struct {
	Running bool `json:"running"`
	PID     int  `json:"pid,omitempty"`
	Port    int  `json:"port,omitempty"`
}

func runProxyStatus(cmd *cobra.Command, args []string) error {
	baseDir := proxyBaseDir()
	fs := afero.NewOsFs()

	running, pid := proxy.IsProxyRunning(fs, baseDir)

	if jsonOutput {
		status := proxyStatusJSON{Running: running}
		if running {
			status.PID = pid
			if port, err := proxy.ReadPortFile(fs, baseDir); err == nil {
				status.Port = port
			}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(status)
	}

	if running {
		port := 0
		if p, err := proxy.ReadPortFile(fs, baseDir); err == nil {
			port = p
		}
		msg := fmt.Sprintf("Proxy is running (PID %d, port %d)", pid, port)
		fmt.Println(statusRunningStyle.Render(msg))
	} else {
		fmt.Println(statusStoppedStyle.Render("Proxy is not running"))
	}

	return nil
}
