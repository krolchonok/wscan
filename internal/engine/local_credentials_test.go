package engine

import (
	"context"
	"fmt"
	"testing"
	"time"
	"wscan/internal/discovery"
	"wscan/internal/domain"
)

func TestLocalCredentialsNeverSendDomainOrUnknownIdentity(t *testing.T) {
	base := discovery.SMBIdentity{ComputerName: "CLIENT", TargetName: "CLIENT", TargetIsServer: true, MachineRole: rolePointer(1)}
	for _, tt := range []struct {
		name string
		id   discovery.SMBIdentity
		cred domain.Credential
	}{
		{"domain-credential", base, domain.Credential{Type: "password", Username: "admin", Domain: "LAB"}},
		{"upn", base, domain.Credential{Type: "password", Username: "admin@lab.local"}},
		{"dc", discovery.SMBIdentity{ComputerName: "DC", TargetName: "LAB", TargetIsDomain: true, MachineRole: rolePointer(5)}, domain.Credential{Type: "password", Username: "admin"}},
		{"unknown", discovery.SMBIdentity{}, domain.Credential{Type: "password", Username: "admin"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			store := &fakeStore{}
			e := New(store, Config{RPS: 10000, TimeoutSeconds: 1})
			called := 0
			r, err := e.sprayLocalCredentials(context.Background(), domain.Project{ID: 1, AllowCredentialAttack: true}, []domain.Service{{Host: "client", Port: 445, Protocol: "smb"}}, []domain.Credential{tt.cred}, LocalSprayOptions{}, func(context.Context, domain.Service, time.Duration) (discovery.SMBIdentity, error) { return tt.id, nil }, func(context.Context, string, time.Duration, string, int, domain.Credential) (bool, error) {
				called++
				return true, nil
			})
			if err != nil || called != 0 || len(r.Attempts) != 1 || !r.Attempts[0].Skipped {
				t.Fatalf("login sent or skip lost: %+v %v called=%d", r, err, called)
			}
		})
	}
}
func TestLocalLedgerSeparatesHostsAndStopsAfterSuccess(t *testing.T) {
	store := &fakeStore{failureCounts: map[string]int{localAttemptKey("a", "admin"): 3}}
	e := New(store, Config{RPS: 10000, TimeoutSeconds: 1})
	calls := 0
	r, err := e.sprayLocalCredentials(context.Background(), domain.Project{ID: 1, AllowCredentialAttack: true}, []domain.Service{{Host: "a", Port: 445, Protocol: "smb"}, {Host: "b", Port: 445, Protocol: "smb"}}, []domain.Credential{{Type: "password", Username: "admin", Secret: "one"}, {Type: "password", Username: "admin", Secret: "two"}}, LocalSprayOptions{}, func(context.Context, domain.Service, time.Duration) (discovery.SMBIdentity, error) {
		return discovery.SMBIdentity{ComputerName: "CLIENT", TargetName: "CLIENT", TargetIsServer: true, MachineRole: rolePointer(1)}, nil
	}, func(_ context.Context, _ string, _ time.Duration, host string, _ int, c domain.Credential) (bool, error) {
		calls++
		if host != "b" || c.Domain != "CLIENT" {
			t.Fatal("wrong local identity")
		}
		return true, nil
	})
	if err != nil || calls != 1 || len(r.Attempts) != 4 || !r.Attempts[0].Skipped || !r.Attempts[1].Success || !r.Attempts[3].Skipped {
		t.Fatalf("%+v %v calls=%d", r, err, calls)
	}
}
func TestLocalPolicyAndAccountLockStop(t *testing.T) {
	threshold := int64(1)
	calls := 0
	e := New(&fakeStore{}, Config{RPS: 10000, TimeoutSeconds: 1})
	identify := func(context.Context, domain.Service, time.Duration) (discovery.SMBIdentity, error) {
		return discovery.SMBIdentity{ComputerName: "CLIENT", TargetName: "CLIENT", TargetIsServer: true, MachineRole: rolePointer(1)}, nil
	}
	login := func(context.Context, string, time.Duration, string, int, domain.Credential) (bool, error) {
		calls++
		return false, fmt.Errorf("STATUS_ACCOUNT_LOCKED_OUT")
	}
	p := domain.Project{ID: 1, AllowCredentialAttack: true}
	targets := []domain.Service{{Host: "client", Port: 445, Protocol: "smb"}}
	creds := []domain.Credential{{Type: "password", Username: "admin"}, {Type: "password", Username: "admin"}}
	r, err := e.sprayLocalCredentials(context.Background(), p, targets, creds, LocalSprayOptions{Policies: map[string]domain.PasswordPolicy{"client": {DN: "client", Source: "local", LockoutThreshold: &threshold}}}, identify, login)
	if err != nil || calls != 0 || !r.Attempts[0].Skipped {
		t.Fatalf("threshold 1 sent a guess: %+v %v", r, err)
	}
	r, err = e.sprayLocalCredentials(context.Background(), p, targets, creds, LocalSprayOptions{}, identify, login)
	if err != nil || calls != 1 || !r.Attempts[1].Skipped {
		t.Fatalf("lockout ignored: %+v %v", r, err)
	}
}

func rolePointer(role int) *int { return &role }

func TestDomainMemberNTLMTargetIsNotDCRole(t *testing.T) {
	cred, err := localCredential(domain.Credential{Type: "password", Username: "admin"}, discovery.SMBIdentity{ComputerName: "CLIENT2", TargetName: "LAB", TargetIsDomain: true, MachineRole: rolePointer(1)})
	if err != nil || cred.Domain != "CLIENT2" {
		t.Fatal("domain member incorrectly excluded", cred, err)
	}
}
func TestLocalPolicyCacheRejectsDomainAndIsProjectScoped(t *testing.T) {
	e := New(&fakeStore{}, Config{})
	threshold := int64(2)
	e.RememberLocalPolicy(1, domain.PasswordPolicy{DN: "client", Source: "domain", LockoutThreshold: &threshold})
	if _, ok := e.localPolicy(1, "client"); ok {
		t.Fatal("domain policy cached as local")
	}
	e.RememberLocalPolicy(1, domain.PasswordPolicy{DN: "client", Source: "local", LockoutThreshold: &threshold})
	if _, ok := e.localPolicy(2, "client"); ok {
		t.Fatal("policy leaked to another project")
	}
	if _, ok := e.localPolicy(1, "client"); !ok {
		t.Fatal("local policy lost")
	}
}
