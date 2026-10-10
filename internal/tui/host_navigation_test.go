package tui

import "testing"

func TestHostArrowsIncludeAllHostsRow(t *testing.T) {
	for _, hosts := range [][]string{{"10.0.0.16"}, {"10.0.0.16", "10.0.0.17"}} {
		for _, key := range []string{"up", "down", "k", "j"} {
			m := model{screen: "desk", hostOrder: hosts, hostIndex: -1}
			seen := map[int]bool{-1: true}
			for step := 0; step < len(hosts)+1; step++ {
				next, _ := m.updateDesk(key)
				m = next.(model)
				if m.hostIndex < -1 || m.hostIndex >= len(hosts) {
					t.Fatalf("%s: invalid index %d", key, m.hostIndex)
				}
				seen[m.hostIndex] = true
			}
			if len(seen) != len(hosts)+1 || m.hostIndex != -1 {
				t.Fatalf("%s: visited %v, ended at %d", key, seen, m.hostIndex)
			}
		}
	}
}
