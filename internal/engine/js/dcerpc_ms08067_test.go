package js

import (
	"context"
	"testing"
	"time"
)

// TestCheckMS08067FailsCleanlyAgainstUnreachableHost mirrors
// TestCheckZerologonFailsCleanlyAgainstUnreachableHost's reasoning: a
// protocol-accurate fake DCE-RPC+SMB server would be needed to exercise the
// actual vulnerable/patched signal paths, and building one isn't a
// meaningful substitute for testing against a real host — this only covers
// what's verifiable in a sandbox with no Windows target (clean error, no
// panic, no false "vulnerable").
func TestCheckMS08067FailsCleanlyAgainstUnreachableHost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	vulnerable, err := CheckMS08067(ctx, "127.0.0.1", 445, 500*time.Millisecond)
	if err == nil {
		t.Fatal("expected an error dialing an unreachable srvsvc endpoint")
	}
	if vulnerable {
		t.Fatal("must never report vulnerable on a dial/bind failure")
	}
}
