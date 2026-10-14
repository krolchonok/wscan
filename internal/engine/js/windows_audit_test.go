package js

import "testing"

func TestWindowsAuditUnknownAndRiskStates(t *testing.T) {
	r, err := parseWindowsAudit("client", `{"os":{"data":{"version":"6.1.7601"}},"computer":{"data":{"part_of_domain":true,"domain_role":1}},"wdigest":{"data":{"present":false}},"local_policy":{"data":{"min_length":7,"lockout_threshold":0}},"dns_zones":{"error":"Access denied"},"firewall":{"data":[{"profile":1,"enabled":false}]}}`)
	if err != nil {
		t.Fatal(err)
	}
	states := map[string]string{}
	for _, c := range r.Checks {
		states[c.ID] = c.State
	}
	if states["wdigest-storage"] != "candidate" || states["patches"] != "incomplete" || states["firewall-disabled/1"] != "confirmed" || r.Policy == nil || r.Policy.Source != "local" || r.Policy.DN != "client" {
		t.Fatalf("%+v", r)
	}
	r, err = parseWindowsAudit("dc", `{"os":{"data":{"version":"10.0.20348"}},"computer":{"data":{"domain_role":5}},"wdigest":{"data":{"present":true,"value":1}},"local_policy":{"data":{"lockout_threshold":3}}}`)
	if err != nil || r.Policy.Source != "domain" {
		t.Fatal(r, err)
	}
	found := false
	for _, c := range r.Checks {
		if c.ID == "wdigest-storage" && c.State == "confirmed" {
			found = true
		}
	}
	if !found {
		t.Fatal("enabled WDigest missing")
	}
	if _, err = parseWindowsAudit("x", `{"wdigest":`); err == nil {
		t.Fatal("truncated JSON accepted")
	}
}
