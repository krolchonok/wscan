package tui

import "wscan/internal/domain"

// scanProfile is a single standard launch profile: one named choice that sets
// both the check-speed and port-speed limits (plus timeout and retries) at
// once, so a scan can be configured with one decision instead of four. The
// speed values intentionally reuse the per-area presets (speedPresets /
// portSpeedPresets) so the individual preset rows stay consistent with the
// chosen profile.
type scanProfile struct {
	name                 string
	rps, workers         int
	portRPS, portWorkers int
	timeout, retries     int
}

var scanProfiles = []scanProfile{
	{"Скрытный", 5, 4, 100, 32, 15, 1},
	{"Стандартный", 50, 16, 1000, 256, 10, 0},
	{"Быстрый", 200, 64, 10000, 1024, 7, 0},
	{"Агрессивный", 0, 128, 0, 2048, 5, 0},
}

// profileName reports the profile whose every value matches the project, or
// "Вручную" when the current mix does not correspond to a standard profile
// (for example after tuning an individual preset).
func profileName(p domain.Project) string {
	for _, pr := range scanProfiles {
		if pr.rps == p.RPS && pr.workers == p.Concurrency &&
			pr.portRPS == p.DiscoveryRPS && pr.portWorkers == p.DiscoveryConcurrency &&
			pr.timeout == p.TimeoutSeconds && pr.retries == p.Retries {
			return pr.name
		}
	}
	return "Вручную"
}

// cycleProfile applies the next (or previous) standard profile to the project.
func cycleProfile(p domain.Project, key string) domain.Project {
	index := -1
	for i, pr := range scanProfiles {
		if pr.name == profileName(p) {
			index = i
			break
		}
	}
	if index < 0 {
		if key == "left" {
			index = len(scanProfiles) - 1
		} else {
			index = 0
		}
	} else if key == "left" {
		index = (index + len(scanProfiles) - 1) % len(scanProfiles)
	} else {
		index = (index + 1) % len(scanProfiles)
	}
	pr := scanProfiles[index]
	p.RPS, p.Concurrency = pr.rps, pr.workers
	p.DiscoveryRPS, p.DiscoveryConcurrency = pr.portRPS, pr.portWorkers
	p.TimeoutSeconds, p.Retries = pr.timeout, pr.retries
	return p
}
