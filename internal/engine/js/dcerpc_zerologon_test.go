package js

import (
	"context"
	"testing"
	"time"
)

// TestCheckZerologonFailsCleanlyAgainstUnreachableHost locks in that
// CheckZerologon returns a plain (false, error) — never a panic — when the
// target isn't reachable at all. A full positive/negative test against a
// real Netlogon exchange would need a protocol-accurate fake DCE-RPC+EPM
// server (bind negotiation, NDR-encoded NetrServerReqChallenge/
// Authenticate3 request/response) to be worth anything; building one isn't
// a meaningful substitute for testing against a real (or lab) domain
// controller, so this only covers the error path this engine can verify in
// a sandbox with no Windows host available.
func TestCheckZerologonFailsCleanlyAgainstUnreachableHost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	vulnerable, err := CheckZerologon(ctx, "127.0.0.1", "NOTADC", 500*time.Millisecond)
	if err == nil {
		t.Fatal("expected an error dialing an unreachable DCE-RPC endpoint")
	}
	if vulnerable {
		t.Fatal("must not report vulnerable on a dial failure")
	}
}
