package proxy

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/websocket"
	"github.com/rs/zerolog"
)

// StreamableProxy is a WebSocket reverse proxy for MCP Streamable HTTP servers.
// It upgrades an incoming HTTP connection to WebSocket, dials the real MCP server,
// and relays JSON-RPC frames bidirectionally while logging DecisionEntries.
//
// Phase 12 adds:
// - Tool definition pinning via ToolPinStore (rug-pull detection)
// - Injection scanning via InjectionScanner (prompt injection detection)
// - JSON-RPC request tracking via requestTracker (response correlation)
type StreamableProxy struct {
	targetURL    string
	decisionLog  *DecisionLog
	upgrader     websocket.Upgrader
	logger       zerolog.Logger

	// Phase 12: pinning and injection scanning.
	pinStore      *ToolPinStore
	injScanner    *InjectionScanner
	tracker       *requestTracker
	serverID        string
	sessionPinned   bool
	policyConfig    *PolicyConfig
	violationWriter *ViolationWriter
}

// NewStreamableProxy creates a new WebSocket MCP proxy that forwards to the given target URL.
// pinStore, injScanner, and policyConfig can be nil for backward-compatible passthrough mode.
func NewStreamableProxy(targetURL string, dl *DecisionLog, logger zerolog.Logger,
	pinStore *ToolPinStore, injScanner *InjectionScanner, policyConfig *PolicyConfig) *StreamableProxy {
	// Derive serverID from the target URL.
	serverID := targetURL

	return &StreamableProxy{
		targetURL:   targetURL,
		decisionLog: dl,
		upgrader: websocket.Upgrader{
			// Restrict to localhost origins to prevent browser-based attacks (DNS rebinding).
			CheckOrigin: func(r *http.Request) bool {
				origin := r.Header.Get("Origin")
				return origin == "" || origin == "http://127.0.0.1" || origin == "http://localhost"
			},
		},
		logger:       logger,
		pinStore:     pinStore,
		injScanner:   injScanner,
		tracker:      newRequestTracker(),
		serverID:     serverID,
		policyConfig: policyConfig,
	}
}

// SetViolationWriter sets the ViolationWriter for persisting findings to violations.jsonl.
func (p *StreamableProxy) SetViolationWriter(vw *ViolationWriter) {
	p.violationWriter = vw
}

// ServeHTTP implements http.Handler. It upgrades the incoming connection to WebSocket,
// dials the target MCP server's WebSocket endpoint, and relays messages bidirectionally.
func (p *StreamableProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Upgrade incoming connection.
	clientConn, err := p.upgrader.Upgrade(w, r, nil)
	if err != nil {
		p.logger.Error().Err(err).Msg("failed to upgrade client connection")
		return
	}
	defer clientConn.Close()

	// Dial the real MCP server.
	serverConn, _, err := websocket.DefaultDialer.Dial(p.targetURL, nil)
	if err != nil {
		p.logger.Error().Err(err).Str("target", p.targetURL).Msg("failed to dial target MCP server")
		clientConn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseInternalServerErr, "failed to connect to MCP server"))
		return
	}
	defer serverConn.Close()

	// errCh signals when either direction's relay completes.
	errCh := make(chan error, 2)

	// client-to-server relay.
	go func() {
		errCh <- p.relayWebSocket(clientConn, serverConn, "request")
	}()

	// server-to-client relay.
	go func() {
		errCh <- p.relayWebSocket(serverConn, clientConn, "response")
	}()

	// When either relay finishes, close both connections.
	<-errCh
}

// relayWebSocket reads WebSocket messages from src, inspects them for JSON-RPC
// content, logs DecisionEntries, and forwards to dst.
//
// Phase 12 adds the same pinning/scanning logic as MCPWrapper.relayWithInspection.
func (p *StreamableProxy) relayWebSocket(src, dst *websocket.Conn, direction string) error {
	for {
		messageType, data, err := src.ReadMessage()
		if err != nil {
			return fmt.Errorf("read %s: %w", direction, err)
		}

		// Inspect JSON-RPC frame.
		msg, parseErr := ParseJSONRPC(data)
		if parseErr == nil {
			// Phase 12: Track requests, check pins, scan for injection.
			p.inspectMessage(msg, direction)

			entry := DecisionEntry{
				Direction:   direction,
				Method:      msg.Method,
				Decision:    ActionAllow,
				Reason:      "passthrough (Phase 9)",
				Protocol:    "mcp-streamable",
				Destination: p.targetURL,
			}
			p.decisionLog.Record(entry)
			if p.violationWriter != nil && len(entry.Findings) > 0 {
				if err := p.violationWriter.WriteFindings(entry); err != nil {
					p.logger.Warn().Err(err).Msg("failed to write violation entry")
				}
			}
			p.logger.Debug().
				Str("method", msg.Method).
				Str("direction", direction).
				Msg("MCP Streamable JSON-RPC message intercepted")
		} else {
			p.logger.Debug().
				Str("direction", direction).
				Msg("non-JSON-RPC WebSocket message forwarded")
		}

		// ALWAYS forward (Phase 9 passthrough).
		if err := dst.WriteMessage(messageType, data); err != nil {
			return fmt.Errorf("write %s: %w", direction, err)
		}
	}
}

// inspectMessage handles Phase 12 pinning, injection scanning, and notification
// processing for a parsed JSON-RPC message.
func (p *StreamableProxy) inspectMessage(msg *JSONRPCMessage, direction string) {
	switch direction {
	case "request":
		if msg.IsRequest() {
			p.tracker.TrackRequest(msg.ID, msg.Method)
		}

	case "response":
		if msg.IsResponse() {
			p.handleResponse(msg)
		}
		if msg.IsNotification() && msg.Method == "notifications/tools/list_changed" {
			p.logger.Warn().
				Str("server_id", p.serverID).
				Msg("MCP server signaled tool list change (notifications/tools/list_changed)")
		}
	}
}

// handleResponse processes a JSON-RPC response.
func (p *StreamableProxy) handleResponse(msg *JSONRPCMessage) {
	method, ok := p.tracker.ResolveResponse(msg.ID)
	if !ok {
		return
	}

	switch method {
	case "tools/list":
		if msg.Result != nil {
			p.handleToolsListResponse(msg)
		}
	case "tools/call":
		if msg.Result != nil && p.injScanner != nil {
			p.handleToolsCallResponse(msg)
		}
	}
}

// handleToolsListResponse processes a tools/list response for pin checking.
func (p *StreamableProxy) handleToolsListResponse(msg *JSONRPCMessage) {
	tools, err := parseToolsList(msg.Result)
	if err != nil {
		p.logger.Warn().Err(err).Msg("failed to parse tools/list response")
		return
	}

	if p.pinStore == nil {
		return
	}

	if !p.sessionPinned {
		p.handleFirstToolsList(tools)
	} else {
		p.handleSubsequentToolsList(tools)
	}
}

// handleFirstToolsList handles the first tools/list response in a session.
func (p *StreamableProxy) handleFirstToolsList(tools []MCPTool) {
	if err := p.pinStore.Load(); err != nil {
		p.logger.Warn().Err(err).Msg("failed to load pin store -- starting fresh")
	}

	changes, _ := p.pinStore.Check(p.serverID, tools, false)

	if len(changes) == 0 && !p.serverHasPins() {
		if err := p.pinStore.PinAll(p.serverID, tools); err != nil {
			p.logger.Error().Err(err).Msg("failed to auto-pin tools")
		} else {
			if err := p.pinStore.Save(); err != nil {
				p.logger.Warn().Err(err).Msg("failed to save pin store after auto-pin")
			}
			p.logger.Info().
				Str("server_id", p.serverID).
				Int("tools", len(tools)).
				Msg("auto-pinned tools for server (first connection)")
		}
	} else if len(changes) > 0 {
		for _, change := range changes {
			action := ActionWarn
			if p.policyConfig != nil {
				action = p.policyConfig.ActionFor("pin_change_between")
			}
			entry := DecisionEntry{
				Direction: "response",
				Method:    "tools/list",
				Decision:  action,
				Reason: fmt.Sprintf("between-session pin change: tool=%s severity=%s old=%s new=%s",
					change.ToolName, change.Severity, change.OldHash, change.NewHash),
				Protocol:    "mcp-streamable",
				Destination: p.targetURL,
				Findings: []Finding{{
					Scanner:     "pinchange",
					Severity:    string(change.Severity),
					Description: fmt.Sprintf("between-session pin change for tool %s", change.ToolName),
					Pattern:     change.ToolName,
					MatchValue:  fmt.Sprintf("old=%s new=%s", change.OldHash, change.NewHash),
					Decision:    action,
				}},
			}
			p.decisionLog.Record(entry)
			if p.violationWriter != nil {
				if err := p.violationWriter.WriteFindings(entry); err != nil {
					p.logger.Warn().Err(err).Msg("failed to write violation entry")
				}
			}
			p.logger.Warn().
				Str("server_id", p.serverID).
				Str("tool", change.ToolName).
				Str("severity", string(change.Severity)).
				Msg("between-session pin change detected")
		}
	}

	p.pinStore.SetSessionBaseline(p.serverID, tools)
	p.sessionPinned = true
}

// handleSubsequentToolsList handles mid-session pin change detection.
func (p *StreamableProxy) handleSubsequentToolsList(tools []MCPTool) {
	changes, _ := p.pinStore.Check(p.serverID, tools, true)

	for _, change := range changes {
		entry := DecisionEntry{
			Direction: "response",
			Method:    "tools/list",
			Decision:  ActionBlock,
			Reason: fmt.Sprintf("MID-SESSION RUG-PULL: tool=%s severity=%s old=%s new=%s",
				change.ToolName, change.Severity, change.OldHash, change.NewHash),
			Protocol:    "mcp-streamable",
			Destination: p.targetURL,
			Findings: []Finding{{
				Scanner:     "pinchange",
				Severity:    string(change.Severity),
				Description: fmt.Sprintf("mid-session rug-pull for tool %s", change.ToolName),
				Pattern:     change.ToolName,
				MatchValue:  fmt.Sprintf("old=%s new=%s", change.OldHash, change.NewHash),
				Decision:    ActionBlock,
			}},
		}
		p.decisionLog.Record(entry)
		if p.violationWriter != nil {
			if err := p.violationWriter.WriteFindings(entry); err != nil {
				p.logger.Warn().Err(err).Msg("failed to write violation entry")
			}
		}
		p.logger.Error().
			Str("server_id", p.serverID).
			Str("tool", change.ToolName).
			Str("severity", string(change.Severity)).
			Msg("MID-SESSION RUG-PULL DETECTED")
	}

	p.pinStore.SetSessionBaseline(p.serverID, tools)
}

// handleToolsCallResponse scans a tools/call result for prompt injection.
func (p *StreamableProxy) handleToolsCallResponse(msg *JSONRPCMessage) {
	findings := p.injScanner.ScanMessage(msg, "response")
	for _, f := range findings {
		action := ActionWarn
		if p.policyConfig != nil {
			action = p.policyConfig.ActionFor("prompt_injection")
		}
		entry := DecisionEntry{
			Direction:   "response",
			Method:      "tools/call",
			Decision:    action,
			Reason:      fmt.Sprintf("injection finding: %s", f.Description),
			Protocol:    "mcp-streamable",
			Destination: p.targetURL,
			Findings:    []Finding{f},
		}
		p.decisionLog.Record(entry)
		if p.violationWriter != nil {
			if err := p.violationWriter.WriteFindings(entry); err != nil {
				p.logger.Warn().Err(err).Msg("failed to write violation entry")
			}
		}
		p.logger.Warn().
			Str("server_id", p.serverID).
			Str("pattern", f.Pattern).
			Str("severity", f.Severity).
			Msg("prompt injection detected in tool call result")
	}
}

// serverHasPins checks if the pin store contains any pins for this server.
func (p *StreamableProxy) serverHasPins() bool {
	prefix := p.serverID + "::"
	pins := p.pinStore.PinKeys()
	for _, key := range pins {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}
