// Package eventreport provides fire-and-forget reporting of violation events
// and auto-profiles to the SkillLedger hosted service. All HTTP calls are
// non-blocking and failures are logged at Debug level without propagating.
package eventreport

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/skillledger/skillledger/internal/credentials"
)

const (
	// httpTimeout is the per-request HTTP client timeout (generous for POST,
	// not on critical path).
	httpTimeout = 5 * time.Second
	// maxBatchSize is the maximum number of events per POST request.
	maxBatchSize = 100
)

// Event represents a single violation or detection event (D-05 payload).
type Event struct {
	Type      string                 `json:"type"`
	Ecosystem string                 `json:"ecosystem"`
	SkillID   string                 `json:"skill_id"`
	Rule      string                 `json:"rule"`
	Severity  string                 `json:"severity"`
	Details   map[string]interface{} `json:"details,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
}

// EventBatch is the JSON payload sent to the events endpoint.
type EventBatch struct {
	OrgSlug string  `json:"org_slug"`
	Events  []Event `json:"events"`
}

// Profile represents an auto-detected skill capability profile (D-09 payload).
type Profile struct {
	OrgSlug      string    `json:"org_slug"`
	SkillID      string    `json:"skill_id"`
	Ecosystem    string    `json:"ecosystem"`
	Capabilities []string  `json:"capabilities"`
	DetectedAt   time.Time `json:"detected_at"`
}

// Reporter sends violation events and profiles to the hosted service in the
// background using fire-and-forget goroutines.
type Reporter struct {
	done       chan struct{}
	serviceURL string
}

// NewReporter creates a Reporter that will POST to serviceURL.
func NewReporter(serviceURL string) *Reporter {
	return &Reporter{
		done:       make(chan struct{}),
		serviceURL: serviceURL,
	}
}

// ReportEventsAsync sends violation events to the service in the background.
// Events are chunked into batches of maxBatchSize (100). Auth failures and
// network errors are logged at Debug level and do not propagate (D-13).
func (r *Reporter) ReportEventsAsync(orgSlug string, events []Event) {
	go func() {
		defer close(r.done)

		// Step 1: Get auth token.
		creds, err := credentials.EnsureFresh(r.serviceURL)
		if err != nil {
			log.Debug().Err(err).Msg("eventreport: auth failed, skipping event report")
			return
		}

		client := &http.Client{Timeout: httpTimeout}
		endpoint := r.serviceURL + "/ee/v1/events"

		// Step 2: Chunk events and send batches.
		for i := 0; i < len(events); i += maxBatchSize {
			end := i + maxBatchSize
			if end > len(events) {
				end = len(events)
			}

			batch := EventBatch{
				OrgSlug: orgSlug,
				Events:  events[i:end],
			}

			data, err := json.Marshal(batch)
			if err != nil {
				log.Debug().Err(err).Msg("eventreport: failed to marshal event batch")
				continue
			}

			req, err := http.NewRequest("POST", endpoint, bytes.NewReader(data))
			if err != nil {
				log.Debug().Err(err).Msg("eventreport: failed to create request")
				continue
			}
			req.Header.Set("Authorization", "Bearer "+creds.AccessToken)
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			if err != nil {
				log.Debug().Err(err).Msg("eventreport: event POST failed")
				continue
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			log.Debug().Int("status", resp.StatusCode).Int("count", len(batch.Events)).Msg("eventreport: events posted")
		}
	}()
}

// ReportProfileAsync sends a capability profile to the service in the
// background. Auth failures and network errors are logged at Debug level
// and do not propagate (D-14).
func (r *Reporter) ReportProfileAsync(profile Profile) {
	go func() {
		// Step 1: Get auth token.
		creds, err := credentials.EnsureFresh(r.serviceURL)
		if err != nil {
			log.Debug().Err(err).Msg("eventreport: auth failed, skipping profile report")
			return
		}

		client := &http.Client{Timeout: httpTimeout}
		endpoint := r.serviceURL + "/ee/v1/profiles"

		data, err := json.Marshal(profile)
		if err != nil {
			log.Debug().Err(err).Msg("eventreport: failed to marshal profile")
			return
		}

		req, err := http.NewRequest("POST", endpoint, bytes.NewReader(data))
		if err != nil {
			log.Debug().Err(err).Msg("eventreport: failed to create request")
			return
		}
		req.Header.Set("Authorization", "Bearer "+creds.AccessToken)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			log.Debug().Err(err).Msg("eventreport: profile POST failed")
			return
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		log.Debug().Int("status", resp.StatusCode).Msg("eventreport: profile posted")
	}()
}

// WaitForReport blocks until the event report goroutine completes or the
// timeout elapses. Returns true if reporting finished, false on timeout.
// Used by PersistentPostRun to wait briefly for event delivery.
func (r *Reporter) WaitForReport(timeout time.Duration) bool {
	select {
	case <-r.done:
		return true
	case <-time.After(timeout):
		return false
	}
}
