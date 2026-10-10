package engine

import (
	"testing"

	"wscan/internal/domain"
)

func TestTargetsAreAllIPs(t *testing.T) {
	if !targetsAreAllIPs([]string{"http://127.0.0.1:80", "https://10.0.0.1:443"}) {
		t.Fatal("expected all IPs")
	}
	if targetsAreAllIPs([]string{"http://127.0.0.1:80", "https://example.com"}) {
		t.Fatal("mixed should be false")
	}
	if targetsAreAllIPs([]string{"example.com"}) {
		t.Fatal("domain should be false")
	}
}

func TestSkipTemplateOnIPTarget(t *testing.T) {
	cases := []struct {
		src  string
		skip bool
	}{
		{"cloud/aws/something.yaml", true},
		{"dns/mx-fingerprint.yaml", true},
		{"http/takeovers/something.yaml", true},
		{"http/technologies/nginx-version.yaml", false},
		{"network/detection/ssh.yaml", false},
	}
	for _, c := range cases {
		got := skipTemplateOnIPTarget(domain.Template{Source: c.src, ID: c.src})
		if got != c.skip {
			t.Fatalf("%s: skip=%v want %v", c.src, got, c.skip)
		}
	}
}
