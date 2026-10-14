package app

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"wscan/internal/storage"
)

func TestJobDiagnosticsRedactsSecretsWithoutTruncatingErrors(t *testing.T) {
	secret := "fixture-secret-2026"
	detail := "LDAP bind: " + strings.Repeat("network detail ", 100) + "password=" + secret
	j := Job{ID: 7, JobRequest: JobRequest{Targets: []string{"192.0.2.10"}, Options: []string{"auth=password timeout=8s"}}, Status: "failed", Error: detail, FailureStage: "LDAP NTLM bind", Environment: []string{"os=windows arch=amd64"}, CheckErrors: []string{detail}, Journal: []JobEvent{{Time: time.Now(), Message: "https://user:other-secret@host/ $krb5asrep$23$alice@LAB:abcdef"}}}
	text := JobDiagnostics(j, []string{secret})
	for _, leaked := range []string{secret, "other-secret", "abcdef"} {
		if strings.Contains(text, leaked) {
			t.Fatalf("secret leaked: %s", leaked)
		}
	}
	for _, want := range []string{strings.Repeat("network detail ", 100), "failure_stage=LDAP NTLM bind", "os=windows arch=amd64", "192.0.2.10", "auth=password timeout=8s"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing diagnostic %q", want)
		}
	}
}

func TestDiagnosticsKeepLaunchEnvironmentAndLongJournalAfterRestart(t *testing.T) {
	store, err := storage.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	m, err := NewManager(context.Background(), store)
	if err != nil {
		t.Fatal(err)
	}
	j, err := m.Start(JobRequest{Label: "long scan"}, "", func(_ context.Context, emit Reporter) (Outcome, error) {
		for i := 0; i < 600; i++ {
			emit(fmt.Sprintf("request %d", i))
		}
		emit("LDAP bind")
		return Outcome{}, errors.New("connection reset")
	})
	if err != nil {
		t.Fatal(err)
	}
	completed := waitJob(t, m, j.ID)
	if len(completed.Environment) == 0 || completed.FailureStage != "LDAP bind" || completed.JournalDropped != 0 {
		t.Fatalf("missing launch/failure context: %+v", completed)
	}
	copy := completed.Environment[0]
	completed.Environment[0] = "mutated"
	unchanged, _ := m.Get(j.ID)
	if unchanged.Environment[0] != copy {
		t.Fatal("caller mutated launch environment")
	}
	m.Close()
	restored, err := NewManager(context.Background(), store)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	got, _ := restored.Get(j.ID)
	if !reflect.DeepEqual(got.Environment, unchanged.Environment) || got.FailureStage != "LDAP bind" {
		t.Fatal("launch environment or failed step lost on restart")
	}
	text := JobDiagnostics(got, nil)
	if !strings.Contains(text, "request 0\n") || !strings.Contains(text, "request 599\n") {
		t.Fatal("long journal lost its beginning or end")
	}
}
