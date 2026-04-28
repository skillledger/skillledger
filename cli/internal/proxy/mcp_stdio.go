package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// MCPWrapper is a fork-exec pipe wrapper for MCP stdio servers.
// It launches the real MCP server as a child process, owns the stdin/stdout
// pipes, and inspects every JSON-RPC message flowing through them.
//
// Phase 12 adds:
// - Tool definition pinning via ToolPinStore (rug-pull detection)
// - Injection scanning via InjectionScanner (prompt injection detection)
// - JSON-RPC request tracking via requestTracker (response correlation)
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

	// Phase 12: pinning and injection scanning.
	pinStore      *ToolPinStore     // tool pin store for rug-pull detection (nil = passthrough)
	injScanner    *InjectionScanner // prompt injection scanner (nil = passthrough)
	tracker       *requestTracker   // JSON-RPC request ID -> method correlation
	serverID      string            // server identity for pin keying
	sessionPinned bool              // whether session baseline has been set
	policyConfig  *PolicyConfig     // for action lookup on violations (nil = defaults)
}

// NewMCPWrapper creates a new MCP stdio wrapper for the given command.
// The wrapper will launch the command as a child process and relay
// JSON-RPC messages between the parent's stdin/stdout and the child's
// stdin/stdout, inspecting each message and logging decisions.
//
// pinStore, injScanner, and policyConfig can be nil for backward-compatible
// passthrough mode (no pinning, no injection scanning).
func NewMCPWrapper(command string, args []string, skillID string, dl *DecisionLog, logger zerolog.Logger,
	pinStore *ToolPinStore, injScanner *InjectionScanner, policyConfig *PolicyConfig) (*MCPWrapper, error) {
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

	// Derive serverID from skillID if available, otherwise from command name.
	serverID := skillID
	if serverID == "" {
		serverID = command
	}

	return &MCPWrapper{
		cmd:          cmd,
		childIn:      childIn,
		childOut:     childOut,
		decisionLog:  dl,
		skillID:      skillID,
		logger:       logger,
		waitDone:     make(chan struct{}),
		pinStore:     pinStore,
		injScanner:   injScanner,
		tracker:      newRequestTracker(),
		serverID:     serverID,
		policyConfig: policyConfig,
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
//
// RunWithStreams waits for both relay goroutines to finish (in addition to
// the child process exit) to ensure all inspection side effects (pin checks,
// injection scanning, decision log writes) complete before returning.
func (w *MCPWrapper) RunWithStreams(input io.Reader, output io.Writer) error {
	if err := w.cmd.Start(); err != nil {
		return fmt.Errorf("start MCP server: %w", err)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_ = w.relayWithInspection(input, w.childIn, "request")
		w.childIn.Close()
	}()

	go func() {
		defer wg.Done()
		_ = w.relayWithInspection(w.childOut, output, "response")
	}()

	// Wait for the child process to exit.
	waitErr := w.wait()
	// Wait for both relay goroutines to finish processing so all inspection
	// side effects (decision log writes, pin checks) are complete.
	wg.Wait()
	return waitErr
}

// relayWithInspection reads line-delimited messages from src, inspects each
// for JSON-RPC content, logs a DecisionEntry for valid messages, and writes
// every line (including non-JSON-RPC) to dst.
//
// Phase 12 adds:
// - Request tracking (direction "request"): track JSON-RPC request IDs
// - Pin checking (direction "response"): check pins on tools/list responses
// - Injection scanning (direction "response"): scan tools/call results
// - Notification handling: log tools/list_changed notifications
//
// IMPORTANT: All messages are ALWAYS forwarded (passthrough preserved).
// Pin checks and injection scanning happen AFTER forwarding for warn-only mode.
func (w *MCPWrapper) relayWithInspection(src io.Reader, dst io.Writer, direction string) error {
	// 1MB buffer per Pitfall 2: macOS pipe buffer is 16KB, need large read buffer.
	scanner := bufio.NewScanner(src)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()

		msg, err := ParseJSONRPC(line)
		if err == nil {
			// Phase 12: Track requests, check pins, scan for injection.
			w.inspectMessage(msg, direction)

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
		// Flush pipe-backed writers to avoid MCP message delivery stalls.
		if f, ok := dst.(*os.File); ok {
			_ = f.Sync()
		}
	}

	return scanner.Err()
}

// inspectMessage handles Phase 12 pinning, injection scanning, and notification
// processing for a parsed JSON-RPC message. This runs after forwarding (passthrough
// preserved); violations are recorded in the DecisionLog.
func (w *MCPWrapper) inspectMessage(msg *JSONRPCMessage, direction string) {
	switch direction {
	case "request":
		// Track outbound requests for response correlation.
		if msg.IsRequest() {
			w.tracker.TrackRequest(msg.ID, msg.Method)
		}

	case "response":
		if msg.IsResponse() {
			w.handleResponse(msg)
		}
		// Handle notifications from server (direction is "response" on the server->agent pipe).
		if msg.IsNotification() && msg.Method == "notifications/tools/list_changed" {
			w.logger.Warn().
				Str("server_id", w.serverID).
				Msg("MCP server signaled tool list change (notifications/tools/list_changed)")
		}
	}
}

// handleResponse processes a JSON-RPC response by resolving its request method
// and applying pin checks (tools/list) or injection scanning (tools/call).
func (w *MCPWrapper) handleResponse(msg *JSONRPCMessage) {
	method, ok := w.tracker.ResolveResponse(msg.ID)
	if !ok {
		return
	}

	switch method {
	case "tools/list":
		if msg.Result != nil {
			w.handleToolsListResponse(msg)
		}
	case "tools/call":
		if msg.Result != nil && w.injScanner != nil {
			w.handleToolsCallResponse(msg)
		}
	}
}

// handleToolsListResponse processes a tools/list response for pin checking.
func (w *MCPWrapper) handleToolsListResponse(msg *JSONRPCMessage) {
	tools, err := parseToolsList(msg.Result)
	if err != nil {
		w.logger.Warn().Err(err).Msg("failed to parse tools/list response")
		return
	}

	if w.pinStore == nil {
		return
	}

	if !w.sessionPinned {
		// First tools/list in session.
		w.handleFirstToolsList(tools)
	} else {
		// Subsequent tools/list (e.g., after notifications/tools/list_changed).
		w.handleSubsequentToolsList(tools)
	}
}

// handleFirstToolsList handles the first tools/list response in a session.
// It loads persisted pins, checks for between-session changes, auto-pins
// on first connection (SSH known_hosts model), and sets the session baseline.
func (w *MCPWrapper) handleFirstToolsList(tools []MCPTool) {
	// Load persisted pins from disk.
	if err := w.pinStore.Load(); err != nil {
		w.logger.Warn().Err(err).Msg("failed to load pin store -- starting fresh")
	}

	// Check for between-session changes.
	changes, _ := w.pinStore.Check(w.serverID, tools, false)

	if len(changes) == 0 && !w.serverHasPins() {
		// First connection ever for this server: auto-pin all tools.
		if err := w.pinStore.PinAll(w.serverID, tools); err != nil {
			w.logger.Error().Err(err).Msg("failed to auto-pin tools")
		} else {
			if err := w.pinStore.Save(); err != nil {
				w.logger.Warn().Err(err).Msg("failed to save pin store after auto-pin")
			}
			w.logger.Info().
				Str("server_id", w.serverID).
				Int("tools", len(tools)).
				Msg("auto-pinned tools for server (first connection)")
		}
	} else if len(changes) > 0 {
		// Between-session changes detected.
		for _, change := range changes {
			action := ActionWarn
			if w.policyConfig != nil {
				action = w.policyConfig.ActionFor("pin_change_between")
			}
			entry := DecisionEntry{
				Direction: "response",
				Method:    "tools/list",
				Decision:  action,
				Reason: fmt.Sprintf("between-session pin change: tool=%s severity=%s old=%s new=%s",
					change.ToolName, change.Severity, change.OldHash, change.NewHash),
				Protocol: "mcp-stdio",
				SkillID:  w.skillID,
				Findings: []Finding{{
					Scanner:     "pinchange",
					Severity:    string(change.Severity),
					Description: fmt.Sprintf("between-session pin change for tool %s", change.ToolName),
					Pattern:     change.ToolName,
					MatchValue:  fmt.Sprintf("old=%s new=%s", change.OldHash, change.NewHash),
					Decision:    action,
				}},
			}
			w.decisionLog.Record(entry)
			w.logger.Warn().
				Str("server_id", w.serverID).
				Str("tool", change.ToolName).
				Str("severity", string(change.Severity)).
				Str("old_hash", change.OldHash).
				Str("new_hash", change.NewHash).
				Msg("between-session pin change detected")
		}
	}

	// Set session baseline for mid-session detection.
	w.pinStore.SetSessionBaseline(w.serverID, tools)
	w.sessionPinned = true
}

// handleSubsequentToolsList handles a tools/list response after the session
// baseline has been established. Mid-session changes are ALWAYS blocked per CONTEXT.md.
func (w *MCPWrapper) handleSubsequentToolsList(tools []MCPTool) {
	changes, _ := w.pinStore.Check(w.serverID, tools, true)

	for _, change := range changes {
		// Mid-session rug-pull: ALWAYS block regardless of policy (CONTEXT.md).
		entry := DecisionEntry{
			Direction: "response",
			Method:    "tools/list",
			Decision:  ActionBlock,
			Reason: fmt.Sprintf("MID-SESSION RUG-PULL: tool=%s severity=%s old=%s new=%s",
				change.ToolName, change.Severity, change.OldHash, change.NewHash),
			Protocol: "mcp-stdio",
			SkillID:  w.skillID,
			Findings: []Finding{{
				Scanner:     "pinchange",
				Severity:    string(change.Severity),
				Description: fmt.Sprintf("mid-session rug-pull for tool %s", change.ToolName),
				Pattern:     change.ToolName,
				MatchValue:  fmt.Sprintf("old=%s new=%s", change.OldHash, change.NewHash),
				Decision:    ActionBlock,
			}},
		}
		w.decisionLog.Record(entry)
		w.logger.Error().
			Str("server_id", w.serverID).
			Str("tool", change.ToolName).
			Str("severity", string(change.Severity)).
			Str("old_hash", change.OldHash).
			Str("new_hash", change.NewHash).
			Msg("MID-SESSION RUG-PULL DETECTED")
	}

	// Update session baseline with current tools.
	w.pinStore.SetSessionBaseline(w.serverID, tools)
}

// handleToolsCallResponse scans a tools/call result for prompt injection.
func (w *MCPWrapper) handleToolsCallResponse(msg *JSONRPCMessage) {
	findings := w.injScanner.ScanMessage(msg, "response")
	for _, f := range findings {
		action := ActionWarn
		if w.policyConfig != nil {
			action = w.policyConfig.ActionFor("prompt_injection")
		}
		entry := DecisionEntry{
			Direction: "response",
			Method:    "tools/call",
			Decision:  action,
			Reason:    fmt.Sprintf("injection finding: %s", f.Description),
			Protocol:  "mcp-stdio",
			SkillID:   w.skillID,
			Findings:  []Finding{f},
		}
		w.decisionLog.Record(entry)
		w.logger.Warn().
			Str("server_id", w.serverID).
			Str("pattern", f.Pattern).
			Str("severity", f.Severity).
			Msg("prompt injection detected in tool call result")
	}
}

// serverHasPins checks if the pin store contains any pins for this server.
func (w *MCPWrapper) serverHasPins() bool {
	// Check the pin store for any entries with this server's prefix.
	prefix := w.serverID + "::"
	pins := w.pinStore.PinKeys()
	for _, key := range pins {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
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
