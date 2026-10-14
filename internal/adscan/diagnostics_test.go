package adscan

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

func TestAccessFailurePreservesErrorTypesAndNetworkContext(t *testing.T) {
	underlying := errors.New("connection reset by peer")
	op := &net.OpError{Op: "read", Net: "tcp", Source: &net.TCPAddr{IP: net.ParseIP("192.0.2.2"), Port: 4567}, Addr: &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 636}, Err: underlying}
	err := accessFailure("LDAPS bind", time.Now(), op)
	if !errors.Is(err, underlying) {
		t.Fatal("network cause no longer unwraps")
	}
	for _, want := range []string{"LDAPS bind", "elapsed=", "op=read", "local=192.0.2.2:4567", "remote=192.0.2.10:636", "timeout=false"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("missing network context: %s", err)
		}
	}
	denied := accessFailure("LDAP bind", time.Now(), ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("invalid credentials")))
	if accessErrorState(denied) != "denied" || !strings.Contains(denied.Error(), "ldap_code=49") {
		t.Fatalf("LDAP code or classification lost: %v", denied)
	}
}
