package proxy

import "net/http"

// InjectProtocolHeader sets the SkillLedger proxy protocol header on a request
// for internal tracking. This header MUST be stripped before forwarding to the
// destination (see StripProtocolHeader and threat T-09-04).
func InjectProtocolHeader(r *http.Request) {
	r.Header.Set(ProtocolHeader, ProtocolVersion)
}

// StripProtocolHeader removes the SkillLedger proxy protocol header from a
// request before it is forwarded to the destination. This prevents information
// disclosure about the proxy to external servers (T-09-04).
func StripProtocolHeader(r *http.Request) {
	r.Header.Del(ProtocolHeader)
}
