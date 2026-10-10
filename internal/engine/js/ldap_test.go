package js

import (
	"context"
	"testing"
	"time"
)

func TestDialLDAPURLDefaultsSchemeAndPort(t *testing.T) {
	// No listener on this port — we only care that URL/endpoint resolution
	// picks the right scheme/port before the dial itself fails.
	_, err := dialLDAPURL(context.Background(), 50*time.Millisecond, "127.0.0.1:1", LDAPConfig{})
	if err == nil {
		t.Fatal("expected a dial error against a closed port")
	}
	// A real dial error (not "unsupported ldap url schema") proves the bare
	// "host:port" (no scheme) form defaulted to ldap:// rather than being
	// rejected outright.
	if got := err.Error(); got == `unsupported ldap url schema ""` {
		t.Fatalf("bare host:port must default to ldap://, got scheme-rejection error: %v", err)
	}
}

func TestDialLDAPURLRejectsUnsupportedScheme(t *testing.T) {
	_, err := dialLDAPURL(context.Background(), time.Second, "cldap://127.0.0.1:389", LDAPConfig{})
	if err == nil {
		t.Fatal("expected an error for an unsupported ldap url scheme")
	}
}

func TestDecodeADTimestampSpecialValues(t *testing.T) {
	if got := DecodeADTimestamp("0"); got != "Not Set" {
		t.Fatalf("DecodeADTimestamp(0) = %q, want \"Not Set\"", got)
	}
	if got := DecodeADTimestamp("9223372036854775807"); got != "Not Set" {
		t.Fatalf("DecodeADTimestamp(max int64) = %q, want \"Not Set\"", got)
	}
	// 132036744000000000 is a real AD FILETIME sample from nuclei's own
	// DecodeADTimestamp doc example.
	if got := DecodeADTimestamp("132036744000000000"); got == "" || got == "Not Set" {
		t.Fatalf("DecodeADTimestamp(real sample) = %q, want a decoded date", got)
	}
}

func TestDecodeZuluTimestampInvalidReturnsEmpty(t *testing.T) {
	if got := DecodeZuluTimestamp("not-a-timestamp"); got != "" {
		t.Fatalf("DecodeZuluTimestamp(invalid) = %q, want empty string", got)
	}
	if got := DecodeZuluTimestamp("2021-08-25T10:00:00Z"); got == "" {
		t.Fatal("DecodeZuluTimestamp(valid RFC3339) must not be empty")
	}
}

func TestJoinFiltersAndNegativeFilter(t *testing.T) {
	got := JoinFilters(FilterIsPerson, FilterAccountEnabled)
	want := "(&" + FilterIsPerson + FilterAccountEnabled + ")"
	if got != want {
		t.Fatalf("JoinFilters = %q, want %q", got, want)
	}
	if got := NegativeFilter(FilterIsPerson); got != "(!"+FilterIsPerson+")" {
		t.Fatalf("NegativeFilter = %q", got)
	}
}

func TestBaseDNFromRealm(t *testing.T) {
	if got := baseDNFromRealm("acme.com"); got != "dc=acme,dc=com" {
		t.Fatalf("baseDNFromRealm(acme.com) = %q, want dc=acme,dc=com", got)
	}
}

// TestLDAPClientMethodsRequireConnection locks in that every method refuses
// cleanly (an error, not a panic/nil-deref) on a zero-value client — the
// shape every call site in tryLogin and future enumeration code relies on.
func TestLDAPClientMethodsRequireConnection(t *testing.T) {
	c := &LDAPClient{}
	if _, err := c.Authenticate("u", "p"); err == nil {
		t.Fatal("Authenticate on an unconnected client must error")
	}
	if _, err := c.AuthenticateWithNTLMHash("u", "hash"); err == nil {
		t.Fatal("AuthenticateWithNTLMHash on an unconnected client must error")
	}
	if _, err := c.Search("(objectClass=*)", "cn"); err == nil {
		t.Fatal("Search on an unconnected client must error")
	}
	if _, err := c.CollectMetadata(); err == nil {
		t.Fatal("CollectMetadata on an unconnected client must error")
	}
	if _, err := c.GetVersion(); err == nil {
		t.Fatal("GetVersion on an unconnected client must error")
	}
	if _, err := c.FindADObjects(FilterIsPerson); err == nil {
		t.Fatal("FindADObjects on an unconnected client must error")
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close on a never-dialed client must be a no-op, got %v", err)
	}
}
