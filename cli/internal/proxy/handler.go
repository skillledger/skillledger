package proxy

import (
	"net/http"

	"github.com/elazarl/goproxy"
	"github.com/rs/zerolog"
)

// Handler implements the request/response handler pipeline for the MITM proxy.
// It logs every intercepted request and response as a DecisionEntry.
type Handler struct {
	decisionLog *DecisionLog
	logger      zerolog.Logger
}

// NewHandler creates a new Handler backed by the given decision log.
func NewHandler(dl *DecisionLog, logger zerolog.Logger) *Handler {
	return &Handler{
		decisionLog: dl,
		logger:      logger,
	}
}

// OnRequest handles an intercepted HTTP request. It injects the protocol header
// for internal tracking, records a DecisionEntry, strips the protocol header
// before forwarding (T-09-04), and passes the request through.
// Phase 9 operates in passthrough mode -- no blocking.
func (h *Handler) OnRequest(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	// Inject protocol header for internal tracking.
	InjectProtocolHeader(r)

	scheme := "http"
	if r.URL.Scheme != "" {
		scheme = r.URL.Scheme
	}
	if r.TLS != nil {
		scheme = "https"
	}

	entry := DecisionEntry{
		ActionID:    NewActionID(),
		Direction:   "request",
		Destination: r.URL.Host,
		Method:      r.Method,
		Decision:    ActionAllow,
		Reason:      "passthrough (Phase 9)",
		Protocol:    scheme,
	}
	h.decisionLog.Record(entry)

	// Store action ID for response correlation.
	ctx.UserData = entry.ActionID

	h.logger.Debug().
		Str("action_id", entry.ActionID).
		Str("method", r.Method).
		Str("host", r.URL.Host).
		Msg("proxy request")

	// Strip protocol header before forwarding to destination (T-09-04).
	StripProtocolHeader(r)

	return r, nil
}

// OnResponse handles an intercepted HTTP response. It records a DecisionEntry
// correlated with the original request via the action ID stored in ctx.UserData.
func (h *Handler) OnResponse(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	entry := DecisionEntry{
		Direction: "response",
		Decision:  ActionAllow,
		Reason:    "passthrough (Phase 9)",
	}

	// Correlate with request action ID if available.
	if actionID, ok := ctx.UserData.(string); ok {
		entry.ActionID = actionID + "-resp"
	}

	if ctx.Req != nil {
		entry.Destination = ctx.Req.URL.Host
		entry.Method = ctx.Req.Method
	}

	h.decisionLog.Record(entry)

	h.logger.Debug().
		Str("action_id", entry.ActionID).
		Str("direction", "response").
		Msg("proxy response")

	return resp
}
