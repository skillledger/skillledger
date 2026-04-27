package proxy_test

import (
	"fmt"
	"sync"
	"testing"

	"github.com/skillledger/skillledger/internal/proxy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProfiler_ObserveHTTP(t *testing.T) {
	p := proxy.NewProfiler()

	p.Observe(proxy.RuntimeAction{
		SkillID:     "skill-1",
		ActionType:  "http_request",
		Destination: "api.example.com:443",
		Method:      "GET",
	})
	p.Observe(proxy.RuntimeAction{
		SkillID:     "skill-1",
		ActionType:  "http_request",
		Destination: "cdn.example.com:443",
		Method:      "GET",
	})
	p.Observe(proxy.RuntimeAction{
		SkillID:     "skill-1",
		ActionType:  "http_request",
		Destination: "auth.example.com:443",
		Method:      "POST",
	})

	m, err := p.Export("skill-1")
	require.NoError(t, err)
	require.Len(t, m.Capabilities.Network, 3)
	// Sorted alphabetically
	assert.Equal(t, "api.example.com:443", m.Capabilities.Network[0])
	assert.Equal(t, "auth.example.com:443", m.Capabilities.Network[1])
	assert.Equal(t, "cdn.example.com:443", m.Capabilities.Network[2])
}

func TestProfiler_ObserveMCPTool(t *testing.T) {
	p := proxy.NewProfiler()

	p.Observe(proxy.RuntimeAction{
		SkillID:    "skill-mcp",
		ActionType: "mcp_tool_call",
		ToolName:   "read_file",
	})
	p.Observe(proxy.RuntimeAction{
		SkillID:    "skill-mcp",
		ActionType: "mcp_tool_call",
		ToolName:   "write_file",
	})

	m, err := p.Export("skill-mcp")
	require.NoError(t, err)
	require.Len(t, m.Capabilities.Tools, 2)
	assert.Equal(t, "read_file", m.Capabilities.Tools[0])
	assert.Equal(t, "write_file", m.Capabilities.Tools[1])
}

func TestProfiler_ObserveMCPResource(t *testing.T) {
	p := proxy.NewProfiler()

	p.Observe(proxy.RuntimeAction{
		SkillID:    "skill-res",
		ActionType: "mcp_resource_access",
		Resource:   "file:///tmp/data.json",
	})

	// Resources are observed but manifest.Capabilities has no Resources field,
	// so they are tracked internally and available via ProfileFor.
	dests, tools, resources, count, found := p.ProfileFor("skill-res")
	require.True(t, found)
	assert.Empty(t, dests)
	assert.Empty(t, tools)
	assert.Equal(t, []string{"file:///tmp/data.json"}, resources)
	assert.Equal(t, 1, count)
}

func TestProfiler_NormalizeDestination(t *testing.T) {
	p := proxy.NewProfiler()

	p.Observe(proxy.RuntimeAction{
		SkillID:     "skill-norm",
		ActionType:  "http_request",
		Destination: "api.openai.com:443/v1/chat",
		Method:      "POST",
	})

	m, err := p.Export("skill-norm")
	require.NoError(t, err)
	require.Len(t, m.Capabilities.Network, 1)
	assert.Equal(t, "api.openai.com:443", m.Capabilities.Network[0])
}

func TestProfiler_DeduplicateDestinations(t *testing.T) {
	p := proxy.NewProfiler()

	for i := 0; i < 5; i++ {
		p.Observe(proxy.RuntimeAction{
			SkillID:     "skill-dedup",
			ActionType:  "http_request",
			Destination: "api.example.com:443",
			Method:      "GET",
		})
	}

	m, err := p.Export("skill-dedup")
	require.NoError(t, err)
	require.Len(t, m.Capabilities.Network, 1)
	assert.Equal(t, "api.example.com:443", m.Capabilities.Network[0])
}

func TestProfiler_MemoryCap(t *testing.T) {
	p := proxy.NewProfiler()

	for i := 0; i < 1001; i++ {
		p.Observe(proxy.RuntimeAction{
			SkillID:     "skill-cap",
			ActionType:  "http_request",
			Destination: fmt.Sprintf("host-%d.example.com:443", i),
			Method:      "GET",
		})
	}

	m, err := p.Export("skill-cap")
	require.NoError(t, err)
	assert.Len(t, m.Capabilities.Network, 1000, "destinations should be capped at maxProfileEntries")
}

func TestProfiler_MultipleSkills(t *testing.T) {
	p := proxy.NewProfiler()

	p.Observe(proxy.RuntimeAction{
		SkillID:     "skill-a",
		ActionType:  "http_request",
		Destination: "a.example.com:443",
		Method:      "GET",
	})
	p.Observe(proxy.RuntimeAction{
		SkillID:     "skill-b",
		ActionType:  "http_request",
		Destination: "b.example.com:443",
		Method:      "POST",
	})

	ids := p.List()
	assert.Equal(t, []string{"skill-a", "skill-b"}, ids)

	mA, err := p.Export("skill-a")
	require.NoError(t, err)
	assert.Equal(t, "skill-a", mA.ID)
	assert.Equal(t, []string{"a.example.com:443"}, mA.Capabilities.Network)

	mB, err := p.Export("skill-b")
	require.NoError(t, err)
	assert.Equal(t, "skill-b", mB.ID)
	assert.Equal(t, []string{"b.example.com:443"}, mB.Capabilities.Network)
}

func TestProfiler_ExportUnknownSkill(t *testing.T) {
	p := proxy.NewProfiler()

	_, err := p.Export("nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no profile for skill")
}

func TestProfiler_ExportAll(t *testing.T) {
	p := proxy.NewProfiler()

	p.Observe(proxy.RuntimeAction{SkillID: "charlie", ActionType: "http_request", Destination: "c.com:80", Method: "GET"})
	p.Observe(proxy.RuntimeAction{SkillID: "alpha", ActionType: "http_request", Destination: "a.com:80", Method: "GET"})
	p.Observe(proxy.RuntimeAction{SkillID: "bravo", ActionType: "http_request", Destination: "b.com:80", Method: "GET"})

	all := p.ExportAll()
	require.Len(t, all, 3)
	assert.Equal(t, "alpha", all[0].ID)
	assert.Equal(t, "bravo", all[1].ID)
	assert.Equal(t, "charlie", all[2].ID)
}

func TestProfiler_DraftVersion(t *testing.T) {
	p := proxy.NewProfiler()

	p.Observe(proxy.RuntimeAction{
		SkillID:    "skill-ver",
		ActionType: "mcp_tool_call",
		ToolName:   "test_tool",
	})

	m, err := p.Export("skill-ver")
	require.NoError(t, err)
	assert.Equal(t, "0.0.0-draft", m.Version)
	assert.Equal(t, 1, m.SkillLedger)
	assert.Equal(t, "skill", m.Kind)
}

func TestProfiler_ConcurrentObserve(t *testing.T) {
	p := proxy.NewProfiler()
	var wg sync.WaitGroup

	for g := 0; g < 10; g++ {
		wg.Add(1)
		go func(goroutine int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				p.Observe(proxy.RuntimeAction{
					SkillID:     fmt.Sprintf("skill-%d", goroutine%3),
					ActionType:  "http_request",
					Destination: fmt.Sprintf("host-%d-%d.example.com:443", goroutine, i),
					Method:      "GET",
				})
			}
		}(g)
	}

	wg.Wait()

	// Should have 3 skills (goroutine%3 produces 0,1,2)
	ids := p.List()
	assert.Len(t, ids, 3)

	// All manifests should export without error
	all := p.ExportAll()
	assert.Len(t, all, 3)
}
