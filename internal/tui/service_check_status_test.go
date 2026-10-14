package tui

import (
	"testing"

	"wscan/internal/domain"
	"wscan/internal/engine"
)

func TestServiceChecksIgnoreAuxiliaryTasks(t *testing.T) {
	service := domain.Service{Host: "192.0.2.10", Port: 445, Protocol: "tcp"}
	for _, kind := range []string{"ad-access", "module", jobDiscover, jobAlive, jobPTR} {
		for _, status := range []string{statusRunning, statusDone, statusFailed, statusCancelled} {
			t.Run(kind+"/"+status, func(t *testing.T) {
				auxiliary := &job{projectID: 1, kind: kind, targets: []string{service.Host}, status: status, result: &engine.Result{Errors: []string{"LDAP connection reset"}}}
				m := model{current: domain.Project{ID: 1}, jobs: []*job{auxiliary}}
				if got := m.serviceCheckStatus(service.Host, service); got != "Нет данных о выполненных проверках" {
					t.Fatalf("auxiliary task changed an unscanned service status: %s", got)
				}
				if got := m.serviceResultErrors(service.Host, service); got != 0 {
					t.Fatalf("auxiliary task added %d service errors", got)
				}
				// A later interaction must not hide an actual scan or its errors.
				m.jobs = []*job{{projectID: 1, kind: jobPort, targets: []string{service.Host}, service: &service, status: statusDone, result: &engine.Result{Errors: []string{"scan timeout"}}}, auxiliary}
				if got := m.serviceCheckStatus(service.Host, service); got != "Завершены с ошибками · g журнал" {
					t.Fatalf("auxiliary task hid the previous scan status: %s", got)
				}
				if got := m.serviceResultErrors(service.Host, service); got != 1 {
					t.Fatalf("previous scan error count = %d, want 1", got)
				}
			})
		}
	}
}

func TestServiceChecksRetainScanFailuresAndScope(t *testing.T) {
	service := domain.Service{Host: "192.0.2.10", Port: 445, Protocol: "tcp"}
	for _, kind := range []string{jobChecks, jobFull, jobPort, jobBulkPort, jobAD} {
		t.Run(kind, func(t *testing.T) {
			j := &job{projectID: 1, kind: kind, targets: []string{service.Host}, service: &service, status: statusFailed}
			m := model{current: domain.Project{ID: 1}, jobs: []*job{j}}
			if got := m.serviceCheckStatus(service.Host, service); got != "Ошибка · g журнал" {
				t.Fatalf("actual scan failure hidden: %s", got)
			}
			other := service
			other.Port = 636
			if got := m.serviceCheckStatus(service.Host, other); got != "Нет данных о выполненных проверках" {
				t.Fatalf("scan failure leaked to another port: %s", got)
			}
			other = service
			other.Protocol = "udp"
			if got := m.serviceCheckStatus(service.Host, other); got != "Нет данных о выполненных проверках" {
				t.Fatalf("scan failure leaked to another protocol: %s", got)
			}
			m.current.ID = 2
			if got := m.serviceCheckStatus(service.Host, service); got != "Нет данных о выполненных проверках" {
				t.Fatalf("scan failure leaked to another project: %s", got)
			}
		})
	}
}
