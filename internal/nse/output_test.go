package nse

import "testing"

func TestOutputIsNoise(t *testing.T) {
	cases := []struct {
		id, out string
		want    bool
	}{
		{"http-google-malware", "No API key found. Use the http-google-malware.api argument", true},
		{"http-title", "Site doesn't have a title.", true},
		{"http-title", "Site doesn't have a title (text/html).", true},
		{"http-title", "Go ahead and ScanMe!", false},
		{"http-headers", "Server: nginx", false},
		{"http-title", "", true},
		{"smb-webexec-exploit", "script-args webexec_command or webexec_gui_command is required to run this script", true},
		{"smb-enum-domains", "Could not negotiate a connection:SMB: ERROR: Server returned less data than it was supposed to (one or more fields are missing); aborting [9]", true},
		{"smb-enum-groups", "Couldn't enumerate groups: Could not negotiate a connection:SMB: ERROR: Server returned less data than it was supposed to (one or more fields are missing); aborting [9]", true},
		{"smb-mbenum", "ERROR: Failed to connect to browser service: Could not negotiate a connection:SMB: ERROR: Server returned less data than it was supposed to (one or more fields are missing); aborting [9]", true},
		{"smb-protocols", "dialects:\n  2.0.2\n  3.1.1", false},
		{"smb2-time", "date: 2026-10-02T12:52:19\nstart_date: N/A", false},
	}
	for _, c := range cases {
		if got := OutputIsNoise(c.id, c.out); got != c.want {
			t.Errorf("OutputIsNoise(%q,%q)=%v want %v", c.id, c.out, got, c.want)
		}
	}
}

func TestOutputIsErrorIgnoresNegotiateNoise(t *testing.T) {
	out := "ERROR: Failed to connect to browser service: Could not negotiate a connection:SMB: ERROR: aborting [9]"
	if OutputIsError(out) {
		t.Fatal("negotiate soft-fail must not be counted as a hard script error")
	}
	if !OutputIsError("ERROR: unexpected Lua panic") {
		t.Fatal("real ERROR: prefix should still count")
	}
}

func TestSMTPConnectionFailuresAreErrors(t *testing.T) {
	for _, output := range []string{
		"Couldn't establish connection on port 25",
		"Could not establish connection on port 587",
		"SMTP failed to send EHLO request.",
		"SMTP EHLO: failed to receive data: connection timeout",
	} {
		if !OutputIsError(output) {
			t.Errorf("transport error treated as a result: %q", output)
		}
	}
	for _, output := range []string{"localhost Hello, STARTTLS, HELP", "214 This server supports EHLO HELP", "250 SMTP AUTH LOGIN"} {
		if OutputIsError(output) {
			t.Errorf("SMTP result treated as an error: %q", output)
		}
	}
}
