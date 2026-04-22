package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// MCPWrapper is a fork-exec pipe wrapper for MCP stdio servers.
// It launches the real MCP server as a child process, owns the stdin/stdout
// pipes, and inspects every JSON-RPC message flowing through them.
// In Phase 9 (passthrough mode), all messages are forwarded without modification.
type MCPWrapper struct {
	cmd         *exec.Cmd
	childIn     io.WriteCloser
	childOut    io.ReadCloser
	decisionLog *DecisionLog
	skillID     string
	logger      zerolog.Logger
	waitOnce    sync.Once
	waitErr     error
	waitDone    chan struct{}
}

// NewMCPWrapper creates a new MCP stdio wrapper for the given command.
// The wrapper will launch the command as a child process and relay
// JSON-RPC messages between the parent's stdin/stdout and the child's
// stdin/stdout, inspecting each message and logging decisions.
func NewMCPWrapper(command string, args []string, skillID string, dl *DecisionLog, logger zerolog.Logger) (*MCPWrapper, error) {
	cmd := exec.Command(command, args...)
	// Pass through stderr so MCP server diagnostics reach the user (RESEARCH.md Pattern 2).
	cmd.Stderr = os.Stderr

	childIn, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("create stdin pipe: %w", err)
	}

	childOut, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("create stdout pipe: %w", err)
	}

	return &MCPWrapper{
		cmd:         cmd,
		childIn:     childIn,
		childOut:    childOut,
		decisionLog: dl,
		skillID:     skillID,
		logger:      logger,
		waitDone:    make(chan struct{}),
	}, nil
}

// wait calls cmd.Wait exactly once via sync.Once and signals waitDone.
func (w *MCPWrapper) wait() error {
	w.waitOnce.Do(func() {
		w.waitErr = w.cmd.Wait()
		close(w.waitDone)
	})
	return w.waitErr
}

// Run starts the child process and relays messages bidirectionally.
// It blocks until the child process exits.
func (w *MCPWrapper) Run() error {
	if err := w.cmd.Start(); err != nil {
		return fmt.Errorf("start MCP server: %w", err)
	}

	// errCh collects relay errors (non-fatal, for logging).
	errCh := make(chan error, 2)

	// agent-to-server: parent stdin -> child stdin
	go func() {
		errCh <- w.relayWithInspection(os.Stdin, w.childIn, "request")
		// Close child stdin when parent stdin is done so the child can detect EOF.
		w.childIn.Close()
	}()

	// server-to-agent: child stdout -> parent stdout
	go func() {
		errCh <- w.relayWithInspection(w.childOut, os.Stdout, "response")
	}()

	// Wait for child process to exit (safe for concurrent calls from Stop).
	return w.wait()
}

// RunWithStreams is like Run but uses the provided reader/writer instead of
// os.Stdin/os.Stdout. This enables testing without capturing the process's
// standard file descriptors.
func (w *MCPWrapper) RunWithStreams(input io.Reader, output io.Writer) error {
	if err := w.cmd.Start(); err != nil {
		return fmt.Errorf("start MCP server: %w", err)
	}

	errCh := make(chan error, 2)

	go func() {
		errCh <- w.relayWithInspection(input, w.childIn, "request")
		w.childIn.Close()
	}()

	go func() {
		errCh <- w.relayWithInspection(w.childOut, output, "response")
	}()

	return w.wait()
}

// relayWithInspection reads line-delimited messages from src, inspects each
// for JSON-RPC content, logs a DecisionEntry for valid messages, and writes
// every line (including non-JSON-RPC) to dst. Phase 9 is passthrough -- no
// messages are ever dropped.
func (w *MCPWrapper) relayWithInspection(src io.Reader, dst io.Writer, direction string) error {
	// 1MB buffer per Pitfall 2: macOS pipe buffer is 16KB, need large read buffer.
	scanner := bufio.NewScanner(src)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()

		msg, err := ParseJSONRPC(line)
		if err == nil {
			entry := DecisionEntry{
				Direction: direction,
				Method:    msg.Method,
				Decision:  ActionAllow,
				Reason:    "passthrough (Phase 9)",
				Protocol:  "mcp-stdio",
				SkillID:   w.skillID,
			}
			w.decisionLog.Record(entry)
			w.logger.Debug().
				Str("method", msg.Method).
				Str("direction", direction).
				Str("skill_id", w.skillID).
				Msg("MCP JSON-RPC message intercepted")
		} else {
			// Non-JSON-RPC line: log at debug level but ALWAYS forward.
			w.logger.Debug().
				Str("direction", direction).
				Msg("non-JSON-RPC line forwarded")
		}

		// ALWAYS write line + newline to dst (Phase 9 passthrough -- NEVER drop messages).
		if _, err := fmt.Fprintf(dst, "%s\n", line); err != nil {
			return fmt.Errorf("write to %s pipe: %w", direction, err)
		}
	}

	return scanner.Err()
}

// Stop sends SIGTERM to the child process and waits for it to exit.
// If the process does not exit within the timeout, it is killed.
func (w *MCPWrapper) Stop() error {
	if w.cmd.Process == nil {
		return nil
	}

	// Send SIGTERM.
	if err := w.cmd.Process.Signal(os.Interrupt); err != nil {
		// Process may already be done.
		return nil
	}

	// Wait with timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	select {
	case <-w.waitDone:
		return w.waitErr
	case <-ctx.Done():
		// Force kill.
		return w.cmd.Process.Kill()
	}
}
