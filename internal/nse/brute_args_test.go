package nse

import "testing"

func TestDefaultBruteArgs(t *testing.T) {
	cases := []struct {
		rps, concurrency int
		wantThreads      string
		wantDelay        string
	}{
		{rps: 50, concurrency: 16, wantThreads: "16", wantDelay: "0.02"},
		{rps: 0, concurrency: 128, wantThreads: "128", wantDelay: ""}, // unlimited RPS -> no delay arg
		{rps: 5, concurrency: 0, wantThreads: "", wantDelay: "0.2"},
	}
	for _, c := range cases {
		got := DefaultBruteArgs(c.rps, c.concurrency)
		if (got["brute.threads"] != c.wantThreads) || (c.wantThreads == "" && got["brute.threads"] != "") {
			t.Errorf("rps=%d concurrency=%d: brute.threads=%q want %q", c.rps, c.concurrency, got["brute.threads"], c.wantThreads)
		}
		if got["brute.delay"] != c.wantDelay {
			t.Errorf("rps=%d concurrency=%d: brute.delay=%q want %q", c.rps, c.concurrency, got["brute.delay"], c.wantDelay)
		}
	}
}
