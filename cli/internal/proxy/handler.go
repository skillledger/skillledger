package proxy

import (
	"bytes"
	"io"
	"net/http"
	"path"

	"github.com/elazarl/goproxy"
	"github.com/rs/zerolog"
)

const (
	// maxBodySize is the maximum request body size read for scanning (10 MB).
	// Bodies exceeding this limit are truncated for scanning purposes only;
	// the original request is forwarded unmodified (CR-02: OOM DoS prevention).
	maxBodySize = 10 * 1024 * 1024
)

// Handler implements the request/response handler pipeline for the MITM proxy.
// It logs every intercepted request and response as a DecisionEntry.
type Handler struct {
	decisionLog     *DecisionLog
	pipeline        *ScanPipeline
	capabilityEval  *RuntimeEvaluator
	trustVerifier   *TrustVerifier
	policyConfig    *PolicyConfig
	violationWriter *ViolationWriter
	logger          zerolog.Logger
}

// NewHandler creates a new Handler backed by the given decision log, scanner pipeline,
// optional RuntimeEvaluator for capability enforcement, optional TrustVerifier for
// provenance-based trust tier lookup, and optional PolicyConfig for per-tier preset selection.
func NewHandler(dl *DecisionLog, pipeline *ScanPipeline, capEval *RuntimeEvaluator, tv *TrustVerifier, pc *PolicyConfig, logger zerolog.Logger) *Handler {
	return &Handler{
		decisionLog:    dl,
		pipeline:       pipeline,
		capabilityEval: capEval,
		trustVerifier:  tv,
		policyConfig:   pc,
		logger:         logger,
	}
}

// SetViolationWriter attaches a ViolationWriter to the handler.
// Findings from decision entries are written to the violation log after recording.
func (h *Handler) SetViolationWriter(vw *ViolationWriter) {
	h.violationWriter = vw
}

// OnRequest handles an intercepted HTTP request. It injects the protocol header
// for internal tracking, reads the request body for scanning, runs the scanner
// pipeline, records a DecisionEntry with findings, strips the protocol header
// before forwarding (T-09-04), and blocks requests matching IOC entries (403).
func (h *Handler) OnRequest(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	// Inject protocol header for internal tracking.
	InjectProtocolHeader(r)

	// Read request body for scanning with size cap (CR-02: OOM DoS prevention).
	// Only the first maxBodySize bytes are scanned; the full body is forwarded.
	var body []byte
	if r.Body != nil {
		var err error
		body, err = io.ReadAll(io.LimitReader(r.Body, maxBodySize+1))
		if err != nil {
			h.logger.Warn().Err(err).Msg("failed to read request body for scanning")
		}
		// Read any remaining body bytes beyond the limit for forwarding.
		remaining, _ := io.ReadAll(r.Body)
		fullBody := body
		if len(remaining) > 0 {
			fullBody = append(body, remaining...)
		}
		r.Body = io.NopCloser(bytes.NewReader(fullBody))
		// Truncate scan input to maxBodySize.
		if len(body) > maxBodySize {
			h.logger.Warn().Int("body_size", len(fullBody)).Int("scan_limit", maxBodySize).
				Msg("request body exceeds scan limit, scanning truncated")
			body = body[:maxBodySize]
		}
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

	// Phase 13: Determine trust tier and per-tier preset for capability evaluation.
	var resolvedTrustTier string
	if h.capabilityEval != nil {
		// Phase 31: Resolve SkillID from header (D-01) or config mapping (D-02).
		skillID := r.Header.Get("X-SkillLedger-SkillID")
		if skillID == "" && h.policyConfig != nil {
			skillID = resolveSkillIDFromMappings(r.URL.Host, h.policyConfig.SkillMappings)
		}
		action := RuntimeAction{
			SkillID:     skillID,
			ActionType:  "http_request",
			Destination: r.URL.Host,
			Method:      r.Method,
		}

		var presetOverride string
		if h.trustVerifier != nil && action.SkillID != "" {
			tier := h.trustVerifier.GetTier(action.SkillID)
			resolvedTrustTier = string(tier)
		}
		if h.policyConfig != nil && resolvedTrustTier != "" {
			presetOverride = h.policyConfig.ProvenancePresetFor(resolvedTrustTier)
		}

		capFindings := h.capabilityEval.Evaluate(r.Context(), action, resolvedTrustTier, presetOverride)
		findings = append(findings, capFindings...)
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
		TrustTier:   resolvedTrustTier,
		Findings:    findings,
	}
	h.decisionLog.Record(entry)

	// Phase 14: Write findings to violation log if present.
	if h.violationWriter != nil {
		if err := h.violationWriter.WriteFindings(entry); err != nil {
			h.logger.Error().Err(err).Msg("failed to write violation")
		}
	}

	// Store action ID for response correlation.
	ctx.UserData = entry.ActionID

	// Log with finding details.
	logEvent := h.logger.Debug().
		Str("action_id", entry.ActionID).
		Str("method", r.Method).
		Str("host", r.URL.Host).
		Str("decision", string(decision))
	if entry.TrustTier != "" {
		logEvent = logEvent.Str("trust_tier", entry.TrustTier)
	}
	if len(findings) > 0 {
		logEvent = logEvent.Int("findings", len(findings))
	}
	logEvent.Msg("proxy request")

	// Phase 31: Strip SkillID header before forwarding (information disclosure prevention, same pattern as T-09-04).
	r.Header.Del("X-SkillLedger-SkillID")

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

	// Phase 14: Write findings to violation log if present.
	if h.violationWriter != nil {
		if err := h.violationWriter.WriteFindings(entry); err != nil {
			h.logger.Error().Err(err).Msg("failed to write violation")
		}
	}

	h.logger.Debug().
		Str("action_id", entry.ActionID).
		Str("direction", "response").
		Msg("proxy response")

	return resp
}

// resolveSkillIDFromMappings matches a request host against config-based
// hostname-to-skillID mappings. Returns "" when no mapping matches.
func resolveSkillIDFromMappings(host string, mappings []SkillMapping) string {
	for _, m := range mappings {
		if matched, _ := path.Match(m.Pattern, host); matched {
			return m.SkillID
		}
	}
	return ""
}
