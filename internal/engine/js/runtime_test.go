package js

import (
	"context"
	"testing"
	"time"
)

// TestAtobBtoa reproduces "ReferenceError: atob is not defined"
// (CVE-2025-53770.yaml, CVE-2025-53771.yaml, CVE-2026-58644.yaml all do
// atob(dg) on a template-provided base64 string) — atob/btoa were never
// registered as globals. Matches real nuclei's pkg/js/global/helpers.go
// exactly: base64.StdEncoding, and atob returns null (not an exception) on
// invalid input.
func TestAtobBtoa(t *testing.T) {
	res := Run(context.Background(), `Export(atob("aGVsbG8="));`, "", nil, nil, "", time.Second)
	if !res.Success {
		t.Fatalf("atob: expected success, err=%q", res.Error)
	}
	if res.Response != "hello" {
		t.Fatalf("atob(\"aGVsbG8=\") = %v, want \"hello\"", res.Response)
	}

	res = Run(context.Background(), `Export(btoa("hello"));`, "", nil, nil, "", time.Second)
	if !res.Success {
		t.Fatalf("btoa: expected success, err=%q", res.Error)
	}
	if res.Response != "aGVsbG8=" {
		t.Fatalf("btoa(\"hello\") = %v, want \"aGVsbG8=\"", res.Response)
	}
}

func TestAtobInvalidReturnsNullNotError(t *testing.T) {
	res := Run(context.Background(), `Export(atob("not valid base64!!!") === null);`, "", nil, nil, "", time.Second)
	if !res.Success {
		t.Fatalf("expected success (atob returns null, doesn't throw), err=%q", res.Error)
	}
	// Export() stringifies (see stringify()/exportBuf), so a boolean comes
	// back as the Go string "true"/"false", not a Go bool.
	if res.Response != "true" {
		t.Fatalf("atob on invalid input must be null, got %v", res.Response)
	}
}

// TestResolveNetBIOSNameAndCheckZerologonAreDefined pins CVE-2020-1472.yaml's
// contract: both globals must exist and run cleanly against an unreachable
// target (null / false, not a ReferenceError) — the same failure mode this
// whole session has repeatedly found for globals a template calls that the
// runtime never registered (see atob/btoa's own history above).
func TestResolveNetBIOSNameAndCheckZerologonAreDefined(t *testing.T) {
	// A 5s ambient timeout, matching a realistic per-request engine budget
	// (not the 1s this test used before the fix below: resolveNetBIOSName's
	// own NBT read used to borrow the full ambient timeout, so a 1s budget
	// starved it outright — exactly the bug
	// TestResolveNetBIOSNameDoesNotStarveTheRestOfTheScript pins).
	res := Run(context.Background(), `Export(resolveNetBIOSName("127.0.0.1") === null);`, "", nil, nil, "", 5*time.Second)
	if !res.Success {
		t.Fatalf("resolveNetBIOSName: expected success, err=%q", res.Error)
	}
	if res.Response != "true" {
		t.Fatalf("resolveNetBIOSName against an unreachable host should be null, got %v", res.Response)
	}

	res = Run(context.Background(), `Export(checkZerologon("127.0.0.1", "NOTADC"));`, "", nil, nil, "", 5*time.Second)
	if !res.Success {
		t.Fatalf("checkZerologon: expected success (errors are swallowed as false, not thrown), err=%q", res.Error)
	}
	if res.Response != "false" {
		t.Fatalf("checkZerologon against an unreachable host should be false, got %v", res.Response)
	}
}

// TestResolveNetBIOSNameDoesNotStarveTheRestOfTheScript reproduces a real
// bug found via live verification of CVE-2020-1472.yaml: a UDP/137 query
// against a port with no listener (very common — NBT is routinely
// firewalled/dropped with no ICMP reply) blocks for the FULL ambient
// script timeout, which left zero budget for checkZerologon's own RPC call
// afterward and made the whole javascript: block time out before it ever
// reached the actual check. resolveNetBIOSName must cap its own wait well
// below a multi-second ambient ScriptTimeout so later calls in the same
// script still get to run.
func TestResolveNetBIOSNameDoesNotStarveTheRestOfTheScript(t *testing.T) {
	start := time.Now()
	res := Run(context.Background(), `
		var name = resolveNetBIOSName("127.0.0.1");
		Export(name === null);
	`, "", nil, nil, "", 5*time.Second)
	elapsed := time.Since(start)
	if !res.Success {
		t.Fatalf("expected success, err=%q", res.Error)
	}
	if res.Response != "true" {
		t.Fatalf("expected null on an unreachable NBT responder, got %v", res.Response)
	}
	if elapsed >= 3*time.Second {
		t.Fatalf("resolveNetBIOSName took %v against a 5s ambient timeout — it must cap its own wait well below that, not consume the whole script budget", elapsed)
	}
}

// TestCheckMS08067IsDefined pins CVE-2008-4250.yaml's contract: the global
// must exist and run cleanly (false, not a ReferenceError or a thrown
// exception) against an unreachable target.
func TestCheckMS08067IsDefined(t *testing.T) {
	res := Run(context.Background(), `Export(checkMS08067("127.0.0.1"));`, "", nil, nil, "", 5*time.Second)
	if !res.Success {
		t.Fatalf("checkMS08067: expected success (errors are swallowed as false, not thrown), err=%q", res.Error)
	}
	if res.Response != "false" {
		t.Fatalf("checkMS08067 against an unreachable host should be false, got %v", res.Response)
	}
}

// TestCheckMS17010IsDefined pins CVE-2017-0143.yaml's contract: the global
// must exist, accept an explicit port (the template tries 445 then 4445),
// and run cleanly against an unreachable target.
func TestCheckMS17010IsDefined(t *testing.T) {
	res := Run(context.Background(), `Export(checkMS17010("127.0.0.1", 4445));`, "", nil, nil, "", 5*time.Second)
	if !res.Success {
		t.Fatalf("checkMS17010: expected success (errors are swallowed as false, not thrown), err=%q", res.Error)
	}
	if res.Response != "false" {
		t.Fatalf("checkMS17010 against an unreachable host should be false, got %v", res.Response)
	}
}
