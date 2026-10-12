package adscan

import (
	"errors"
	"testing"
)

func TestSMBAuthenticationFailureVersusPipePermissions(t *testing.T) {
	for _, tc := range []struct {
		message string
		stop    bool
	}{
		{"bind: ncacn_np: open smb session: permission denied", true},
		{"open smb session: STATUS_LOGON_FAILURE", true},
		{"open file: open eventlog: permission denied", false},
		{"RPC: STATUS_ACCESS_DENIED", false},
		{"open smb session: context deadline exceeded", false},
	} {
		if got := smbAuthenticationRejected(errors.New(tc.message)); got != tc.stop {
			t.Errorf("%q: stop=%v", tc.message, got)
		}
	}
	if smbAuthenticationRejected(nil) {
		t.Fatal("successful SMB must not stop methods")
	}
}
