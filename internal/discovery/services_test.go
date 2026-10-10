package discovery

import "testing"

func TestParsePortList(t *testing.T) {
	got := ParsePortList("22,80,443,8000-8003,80, bad, 70000")
	want := []int{22, 80, 443, 8000, 8001, 8002, 8003}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("at %d got %d want %d (%v)", i, got[i], want[i], got)
		}
	}
	if len(ParsePortList("")) != 0 || len(ParsePortList("abc")) != 0 {
		t.Error("empty/invalid spec should yield no ports")
	}
}

func TestTopPortsFallback(t *testing.T) {
	// With no library dir the data file is absent, so TopPorts must fall back to
	// the built-in common list rather than return nothing.
	tcp := TopPorts("/nonexistent", "tcp", 10)
	if len(tcp) == 0 {
		t.Error("expected a non-empty fallback TCP list")
	}
	udp := TopPorts("/nonexistent", "udp", 10)
	if len(udp) == 0 {
		t.Error("expected a non-empty fallback UDP list")
	}
}
