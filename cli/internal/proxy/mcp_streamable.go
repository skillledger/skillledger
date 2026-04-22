package proxy

import (
	"fmt"
	"net/http"

	"github.com/gorilla/websocket"
	"github.com/rs/zerolog"
)

// StreamableProxy is a WebSocket reverse proxy for MCP Streamable HTTP servers.
// It upgrades an incoming HTTP connection to WebSocket, dials the real MCP server,
// and relays JSON-RPC frames bidirectionally while logging DecisionEntries.
// In Phase 9 (passthrough mode), all messages are forwarded without modification.
type StreamableProxy struct {
	targetURL   string
	decisionLog *DecisionLog
	upgrader    websocket.Upgrader
	logger      zerolog.Logger
}

// NewStreamableProxy creates a new WebSocket MCP proxy that forwards to the given target URL.
func NewStreamableProxy(targetURL string, dl *DecisionLog, logger zerolog.Logger) *StreamableProxy {
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
		logger: logger,
	}
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
// content, logs DecisionEntries, and forwards to dst. Phase 9 passthrough.
func (p *StreamableProxy) relayWebSocket(src, dst *websocket.Conn, direction string) error {
	for {
		messageType, data, err := src.ReadMessage()
		if err != nil {
			return fmt.Errorf("read %s: %w", direction, err)
		}

		// Inspect JSON-RPC frame.
		msg, parseErr := ParseJSONRPC(data)
		if parseErr == nil {
			entry := DecisionEntry{
				Direction:   direction,
				Method:      msg.Method,
				Decision:    ActionAllow,
				Reason:      "passthrough (Phase 9)",
				Protocol:    "mcp-streamable",
				Destination: p.targetURL,
			}
			p.decisionLog.Record(entry)
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
