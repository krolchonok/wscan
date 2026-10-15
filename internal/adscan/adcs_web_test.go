package adscan

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

func adcsFixtureAddress(t *testing.T, handler http.Handler) (string, int) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	host, rawPort, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		t.Fatal(err)
	}
	return host, port
}

func TestProbeADCSClassifiesESC8Candidate(t *testing.T) {
	host, port := adcsFixtureAddress(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/certsrv/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Add("WWW-Authenticate", "Negotiate")
		w.Header().Add("WWW-Authenticate", "NTLM")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("Microsoft Active Directory Certificate Services certsrv"))
	}))

	paths := probeADCS(context.Background(), host, port)
	if len(paths) != 1 {
		t.Fatalf("paths=%+v", paths)
	}
	got := paths[0]
	if got.Kind != "web-enrollment" || got.Scheme != "http" || got.State != "candidate" || !containsFold(got.Auth, "NTLM") || !containsFold(got.Auth, "Negotiate") {
		t.Fatalf("unexpected classification: %+v", got)
	}
}

func TestProbeADCSFindsEnrollmentServicesWithoutCallingThemVulnerable(t *testing.T) {
	host, port := adcsFixtureAddress(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ADPolicyProvider_CEP_Kerberos/service.svc" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("WWW-Authenticate", "Negotiate, NTLM")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("certificate enrollment policy"))
	}))

	paths := probeADCS(context.Background(), host, port)
	if len(paths) != 1 || paths[0].Kind != "enrollment-policy" || paths[0].State != "observed" {
		t.Fatalf("unexpected classification: %+v", paths)
	}
}

func TestAdvertisedHTTPAuthIgnoresMalformedValues(t *testing.T) {
	got := advertisedHTTPAuth([]string{"", "   ", "Negotiate abc, NTLM", "Basic realm=x", "Unknown x"})
	if len(got) != 3 || !containsFold(got, "Negotiate") || !containsFold(got, "NTLM") || !containsFold(got, "Basic") {
		t.Fatalf("auth=%v", got)
	}
}
