package proxy

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/skillledger/skillledger/internal/ioc"
)

// SuspiciousTLDs contains top-level domains frequently associated with
// malicious or phishing activity. Matches produce informational ActionLog
// findings (D-07), not blocking decisions.
var SuspiciousTLDs = map[string]bool{
	".tk": true, ".ml": true, ".ga": true, ".cf": true, ".gq": true,
	".top": true, ".xyz": true, ".win": true, ".bid": true, ".click": true,
	".loan": true, ".racing": true, ".review": true, ".download": true,
	".stream": true, ".science": true, ".party": true, ".date": true,
	".faith": true, ".cricket": true,
}

// NetworkScanner checks outbound request destinations against the IOC domain
// database and a list of suspicious TLDs. IOC matches produce ActionBlock
// findings; suspicious TLD matches produce ActionLog findings.
type NetworkScanner struct {
	iocDB *ioc.Database
}

// NewNetworkScanner creates a NetworkScanner backed by the given IOC database.
func NewNetworkScanner(db *ioc.Database) *NetworkScanner {
	return &NetworkScanner{iocDB: db}
}

// Scan inspects the request destination hostname against IOC entries and
// suspicious TLDs. IOC matches take precedence (ActionBlock); if the domain
// matches an IOC entry, the TLD check is skipped to avoid duplicate findings.
func (s *NetworkScanner) Scan(req *http.Request, body []byte) []Finding {
	hostname := extractHostname(req.URL.Host)
	if hostname == "" {
		return nil
	}

	// Check IOC database first (higher severity, takes precedence).
	if entry, matched := s.iocDB.MatchDomain(hostname); matched {
		return []Finding{{
			Scanner:     "network",
			Severity:    entry.Severity,
			Description: fmt.Sprintf("Destination %s matches IOC entry: %s", hostname, entry.Description),
			Decision:    ActionBlock,
		}}
	}

	// Check suspicious TLD (informational only).
	tld := extractTLD(hostname)
	if tld != "" && SuspiciousTLDs[tld] {
		return []Finding{{
			Scanner:     "network",
			Severity:    "info",
			Description: fmt.Sprintf("Destination %s uses suspicious TLD", hostname),
			Decision:    ActionLog,
		}}
	}

	return nil
}

// extractHostname strips the port from a host:port string.
// Returns the hostname portion only.
func extractHostname(hostport string) string {
	if hostport == "" {
		return ""
	}
	// net.SplitHostPort requires a port; try it first.
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		// No port present -- use as-is.
		return strings.TrimSuffix(hostport, ".")
	}
	return strings.TrimSuffix(host, ".")
}

// extractTLD returns the last dot-delimited segment of the hostname,
// including the leading dot (e.g., ".tk", ".com").
// Returns empty string if hostname has no dots.
func extractTLD(hostname string) string {
	hostname = strings.TrimSuffix(hostname, ".")
	idx := strings.LastIndex(hostname, ".")
	if idx < 0 {
		return ""
	}
	return hostname[idx:]
}
