package proxy

import (
	"fmt"
	"net/url"
	"sort"
	"sync"
	"time"

	"github.com/skillledger/skillledger/internal/manifest"
)

const maxProfileEntries = 1000

// skillProfile tracks observed capabilities for a single skill.
type skillProfile struct {
	destinations map[string]struct{} // unique host:port
	methods      map[string]struct{} // unique HTTP methods
	tools        map[string]struct{} // unique MCP tool names
	resources    map[string]struct{} // unique MCP resource URIs
	firstSeen    time.Time
	actionCount  int
}

// Profiler observes runtime actions and builds draft capability manifests.
// It is safe for concurrent use by multiple goroutines.
type Profiler struct {
	mu       sync.RWMutex
	profiles map[string]*skillProfile
}

// NewProfiler creates a new Profiler ready to observe actions.
func NewProfiler() *Profiler {
	return &Profiler{
		profiles: make(map[string]*skillProfile),
	}
}

// Observe records a runtime action for the associated skill.
// It implements the ActionObserver interface.
func (p *Profiler) Observe(action RuntimeAction) {
	p.mu.Lock()
	defer p.mu.Unlock()

	prof, ok := p.profiles[action.SkillID]
	if !ok {
		prof = &skillProfile{
			destinations: make(map[string]struct{}),
			methods:      make(map[string]struct{}),
			tools:        make(map[string]struct{}),
			resources:    make(map[string]struct{}),
			firstSeen:    time.Now(),
		}
		p.profiles[action.SkillID] = prof
	}

	switch action.ActionType {
	case "http_request":
		dest := normalizeDestination(action.Destination)
		if dest != "" && len(prof.destinations) < maxProfileEntries {
			prof.destinations[dest] = struct{}{}
		}
		if action.Method != "" && len(prof.methods) < maxProfileEntries {
			prof.methods[action.Method] = struct{}{}
		}
	case "mcp_tool_call":
		if action.ToolName != "" && len(prof.tools) < maxProfileEntries {
			prof.tools[action.ToolName] = struct{}{}
		}
	case "mcp_resource_access":
		if action.Resource != "" && len(prof.resources) < maxProfileEntries {
			prof.resources[action.Resource] = struct{}{}
		}
	}

	prof.actionCount++
}

// normalizeDestination strips paths from destinations, returning host:port only.
func normalizeDestination(dest string) string {
	if dest == "" {
		return ""
	}

	// If destination contains a slash, it likely has a path component.
	// Try parsing as URL to extract just the host.
	for i := 0; i < len(dest); i++ {
		if dest[i] == '/' {
			// Add scheme if missing so url.Parse works correctly.
			toParse := dest
			if len(dest) < 8 || (dest[:7] != "http://" && dest[:8] != "https://") {
				toParse = "https://" + dest
			}
			u, err := url.Parse(toParse)
			if err != nil || u.Host == "" {
				return dest
			}
			return u.Host
		}
	}

	return dest
}

// Export generates a draft manifest.Manifest from the observed actions for a skill.
// The manifest uses version "0.0.0-draft" to signal it was auto-generated.
func (p *Profiler) Export(skillID string) (*manifest.Manifest, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	prof, ok := p.profiles[skillID]
	if !ok {
		return nil, fmt.Errorf("no profile for skill %q", skillID)
	}

	m := &manifest.Manifest{
		SkillLedger: 1,
		ID:          skillID,
		Kind:        "skill",
		Version:     "0.0.0-draft",
		Capabilities: manifest.Capabilities{
			Network: setToSortedSlice(prof.destinations),
			Tools:   setToSortedSlice(prof.tools),
		},
	}

	return m, nil
}

// ExportAll generates draft manifests for all observed skills, sorted by skill ID.
func (p *Profiler) ExportAll() []*manifest.Manifest {
	p.mu.RLock()
	ids := make([]string, 0, len(p.profiles))
	for id := range p.profiles {
		ids = append(ids, id)
	}
	p.mu.RUnlock()

	sort.Strings(ids)

	manifests := make([]*manifest.Manifest, 0, len(ids))
	for _, id := range ids {
		m, err := p.Export(id)
		if err == nil {
			manifests = append(manifests, m)
		}
	}
	return manifests
}

// List returns sorted skill IDs for all observed skills.
func (p *Profiler) List() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	ids := make([]string, 0, len(p.profiles))
	for id := range p.profiles {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// ProfileFor returns the observed capabilities for a specific skill.
// It returns sorted slices of destinations, tools, and resources, plus
// the total action count and whether the skill was found.
func (p *Profiler) ProfileFor(skillID string) (destinations, tools, resources []string, actionCount int, found bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	prof, ok := p.profiles[skillID]
	if !ok {
		return nil, nil, nil, 0, false
	}

	return setToSortedSlice(prof.destinations),
		setToSortedSlice(prof.tools),
		setToSortedSlice(prof.resources),
		prof.actionCount,
		true
}

// setToSortedSlice converts a set (map[string]struct{}) to a sorted string slice.
func setToSortedSlice(s map[string]struct{}) []string {
	if len(s) == 0 {
		return nil
	}
	result := make([]string, 0, len(s))
	for k := range s {
		result = append(result, k)
	}
	sort.Strings(result)
	return result
}
