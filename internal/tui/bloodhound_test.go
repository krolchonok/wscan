package tui

import (
	"context"
	"strings"
	"testing"
	"time"

	"wscan/internal/domain"
	"wscan/internal/engine"
)

func TestBloodHoundSetupRequiresCredentialAndShowsScope(t *testing.T) {
	m := newTestModelForSettings(t)
	m.current = domain.Project{ID: 1, Name: "lab"}
	m.screen = "ad-access"
	m.adAccessHost = "dc.lab.example"
	m.adAccessDomain = "lab.example"
	m.adAccessCred = -1
	for i, mode := range adAccessModes {
		if mode.id == "bloodhound-ce" {
			m.adAccessIndex = i
		}
	}
	next, cmd := m.startADAccess()
	m = next.(model)
	if cmd != nil || len(m.jobs) != 0 || !strings.Contains(m.message, "учётку") {
		t.Fatalf("anonymous collection started: %s", m.message)
	}
	next, _ = m.updateADAccess("l")
	m = next.(model)
	port, limit := m.bloodHoundSettings()
	if port != 389 || limit != 5000 {
		t.Fatalf("settings %d %d", port, limit)
	}
	if view := m.viewADAccess(100); !strings.Contains(view, "рабочие станции не опрашиваются") || !strings.Contains(view, "389") {
		t.Fatal(view)
	}
	next, _ = m.updateADAccess("n")
	m = next.(model)
	if m.screen != "input" || m.inputAction != "ad-bloodhound-limit" {
		t.Fatalf("wrong limit input %+v", m)
	}
	m.input = "10000"
	next, _ = m.updateInput(enterKey())
	m = next.(model)
	if m.screen != "ad-access" || m.adBloodHoundLimit != 10000 {
		t.Fatalf("limit not applied %d %s", m.adBloodHoundLimit, m.screen)
	}
}

func TestResponderDebugToggle(t *testing.T) {
	m := model{screen: "coerce-setup"}
	next, _ := m.updateCoercionSetup("v")
	m = next.(model)
	if !m.responderDebug {
		t.Fatal("debug not enabled")
	}
	m.adResponderJobID = 1
	m.jobs = []*job{{id: 1, status: statusRunning}}
	next, _ = m.toggleResponderDebug()
	m = next.(model)
	if !m.responderDebug || !strings.Contains(m.message, "останови") {
		t.Fatal("running receiver options changed silently")
	}
}

func TestSMBDiagnosticIsDeliveredAfterJobCancellation(t *testing.T) {
	m := model{ctx: context.Background(), jobEvents: make(chan jobEvent, 10)}
	m.launch("responder", "test", nil, func(ctx context.Context, emit progressReporter) (engine.Result, error) {
		<-ctx.Done()
		emit("2026-10-12T00:00:00Z [SMB] conn=1 peer=192.0.2.1:50000 SESSION_CLOSED reason=SERVER_CANCELLED")
		return engine.Result{}, ctx.Err()
	})
	m.jobs[0].cancel()
	select {
	case event := <-m.jobEvents:
		if event.done || !strings.Contains(event.stage, "SESSION_CLOSED") {
			t.Fatal(event)
		}
	case <-time.After(time.Second):
		t.Fatal("terminal diagnostic dropped")
	}
	select {
	case event := <-m.jobEvents:
		if !event.done {
			t.Fatal(event)
		}
	case <-time.After(time.Second):
		t.Fatal("job did not finish")
	}
}
