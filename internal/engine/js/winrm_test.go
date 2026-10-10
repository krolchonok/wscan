package js

import (
	"context"
	"testing"
	"time"
)

func TestIdentityFormatsDomainBackslashUser(t *testing.T) {
	if got := identity("", "jdoe"); got != "jdoe" {
		t.Fatalf("identity with no domain = %q, want \"jdoe\"", got)
	}
	if got := identity("CORP", "jdoe"); got != `CORP\jdoe` {
		t.Fatalf(`identity with domain = %q, want "CORP\jdoe"`, got)
	}
}

// TestWinRMConnectFailsCleanlyAgainstClosedPort locks in that Connect
// surfaces a plain error (not a panic) when the target isn't reachable —
// the shape tryLogin's dispatch relies on.
func TestWinRMConnectFailsCleanlyAgainstClosedPort(t *testing.T) {
	c := NewWinRMClient(context.Background(), 200*time.Millisecond)
	ok, err := c.Connect("127.0.0.1", 1, "", "jdoe", "wrong")
	if err == nil {
		t.Fatal("expected an error against a closed port")
	}
	if ok {
		t.Fatal("Connect must not report success on error")
	}
}
