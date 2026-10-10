package tui

import (
	"context"
	"net"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"wscan/internal/discovery"
)

type hostNamesDone struct {
	projectID int64
	names     map[string][]string
}

// Resolve in small background batches so opening a project never waits on DNS.
func (m *model) resolveHostNamesCmd() tea.Cmd {
	if m.current.ID == 0 || m.dnsBusy {
		return nil
	}
	var hosts []string
	for _, host := range m.hostBuckets() {
		if !m.dnsPinned[host] && net.ParseIP(host) != nil && time.Since(m.dnsChecked[host]) >= time.Hour {
			hosts = append(hosts, host)
			if len(hosts) == 64 {
				break
			}
		}
	}
	if len(hosts) == 0 {
		return nil
	}
	m.dnsBusy = true
	projectID, ctx := m.current.ID, m.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	return func() tea.Msg {
		return hostNamesDone{projectID: projectID, names: discovery.ReverseHostNames(ctx, hosts, time.Second)}
	}
}

func (m model) namesForHost(host string) []string {
	return m.hostNames[host]
}
