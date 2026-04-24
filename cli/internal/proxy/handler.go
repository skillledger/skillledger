package proxy

import (
	"bytes"
	"io"
	"net/http"

	"github.com/elazarl/goproxy"
	"github.com/rs/zerolog"
)

// Handler implements the request/response handler pipeline for the MITM proxy.
// It logs every intercepted request and response as a DecisionEntry.
type Handler struct {
	decisionLog *DecisionLog
	pipeline    *ScanPipeline
	logger      zerolog.Logger
}

// NewHandler creates a new Handler backed by the given decision log and scanner pipeline.
func NewHandler(dl *DecisionLog, pipeline *ScanPipeline, logger zerolog.Logger) *Handler {
	return &Handler{
		decisionLog: dl,
		pipeline:    pipeline,
		logger:      logger,
	}
}

// OnRequest handles an intercepted HTTP request. It injects the protocol header
// for internal tracking, reads the request body for scanning, runs the scanner
// pipeline, records a DecisionEntry with findings, strips the protocol header
// before forwarding (T-09-04), and blocks requests matching IOC entries (403).
func (h *Handler) OnRequest(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	// Inject protocol header for internal tracking.
	InjectProtocolHeader(r)

	// Read request body for scanning, restore for forwarding (per D-03: no size limit).
	var body []byte
	if r.Body != nil {
		var err error
		body, err = io.ReadAll(r.Body)
		if err != nil {
			h.logger.Warn().Err(err).Msg("failed to read request body for scanning")
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
	}

	// Run scanner pipeline (per D-12: scanners run BEFORE allow decision).
	decision := ActionAllow
	reason := "no findings"
	var findings []Finding
	if h.pipeline != nil {
		findings = h.pipeline.Run(r, body)
		if len(findings) > 0 {
			decision = HighestDecision(findings)
			reason = FormatFindings(findings)
		}
	}

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
		Decision:    decision,
		Reason:      reason,
		Protocol:    scheme,
	}
	h.decisionLog.Record(entry)

	// Store action ID for response correlation.
	ctx.UserData = entry.ActionID

	// Log with finding details.
	logEvent := h.logger.Debug().
		Str("action_id", entry.ActionID).
		Str("method", r.Method).
		Str("host", r.URL.Host).
		Str("decision", string(decision))
	if len(findings) > 0 {
		logEvent = logEvent.Int("findings", len(findings))
	}
	logEvent.Msg("proxy request")

	// Strip protocol header before forwarding to destination (T-09-04).
	StripProtocolHeader(r)

	// Block request if decision is ActionBlock (per D-13: IOC match default).
	if decision == ActionBlock {
		return r, goproxy.NewResponse(r, goproxy.ContentTypeText, http.StatusForbidden,
			"Blocked by SkillLedger proxy: "+reason)
	}

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
