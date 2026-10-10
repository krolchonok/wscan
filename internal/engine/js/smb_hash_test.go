package js

import (
	"context"
	"testing"
	"time"
)

// TestSMBLoginWithHashRejectsInvalidHex locks in that a malformed NTLM hash
// is refused before any network I/O — domain.Credential{Type: "ntlm-hash"}
// rows come straight from operator input, and a bad hex string here must not
// be confused with "credential didn't work" (a password-spray lockout-safety
// miscount) when it never actually reached the target.
func TestSMBLoginWithHashRejectsInvalidHex(t *testing.T) {
	c := NewSMBClient(context.Background(), time.Second)
	ok, err := c.LoginWithHash("127.0.0.1", 445, "CORP", "jdoe", "not-hex!!")
	if err == nil {
		t.Fatal("expected an error for a non-hex hash")
	}
	if ok {
		t.Fatal("LoginWithHash must not report success on error")
	}
}

func TestSMBLoginWithHashFailsCleanlyAgainstClosedPort(t *testing.T) {
	c := NewSMBClient(context.Background(), 200*time.Millisecond)
	// aad3b435b51404eeaad3b435b51404ee is the well-known empty-LM-hash
	// placeholder, paired with a syntactically valid (if meaningless) NT hash.
	ok, err := c.LoginWithHash("127.0.0.1", 1, "", "jdoe", "31d6cfe0d16ae931b73c59d7e0c089c0")
	if err == nil {
		t.Fatal("expected an error against a closed port")
	}
	if ok {
		t.Fatal("LoginWithHash must not report success on error")
	}
}
