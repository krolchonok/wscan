package tui

import (
	"strings"
	"testing"
	"wscan/internal/domain"
)

func TestADInventoryIsVisibleInDefaultFilterAndPortCards(t *testing.T) {
	host := "10.0.0.10"
	root := domain.Finding{TemplateID: "adscan-rootdse", Name: "Сведения Active Directory из RootDSE", Severity: "info", MatchedAt: host, Target: "10.0.0.0/24", Description: "домен: lab.example; имя контроллера: dc.lab.example"}
	role := domain.Finding{TemplateID: "adscan-role-domain-controller", Name: "Контроллер домена", Severity: "info", MatchedAt: host}
	dns := domain.Finding{TemplateID: "adscan-dns-srv", Name: "AD DNS SRV", Severity: "info", MatchedAt: host}
	generic := domain.Finding{TemplateID: "normal-info", Severity: "info", MatchedAt: host}
	m := model{screen: "desk", hostOrder: []string{host}, inventory: map[string]*hostInfo{host: {findings: []domain.Finding{root, role, dns, generic}}}}
	m.openProjectResults()
	if got := m.filteredProjectFindings(); len(got) != 3 {
		t.Fatalf("default filter hides AD or exposes unrelated info: %+v", got)
	}
	for _, tc := range []struct {
		port int
		want int
	}{{389, 2}, {636, 2}, {88, 1}, {53, 1}, {445, 0}} {
		fs := m.findingsForService(host, domain.Service{Host: host, Port: tc.port, Protocol: "tcp"})
		if len(fs) != tc.want {
			t.Fatalf("%d: got %+v", tc.port, fs)
		}
	}
	m.findingDetail = &root
	if text := strings.Join(m.projectResultDetailLines(100), "\n"); !strings.Contains(text, "lab.example") {
		t.Fatal("AD domain missing in overview")
	}
}

func TestADRootDSEFailureRemainsVisible(t *testing.T) {
	f := adEvidenceFinding("10.0.0.0/24", "10.0.0.10", "rootdse", "LDAP RootDSE", "RootDSE: запрос завершился ошибкой: insufficient access rights", "")
	if f.Evidence == "" {
		t.Fatal("diagnostic evidence not preserved")
	}
	m := model{findingDetail: &f, findingSection: 1}
	text := strings.Join(m.projectResultDetailLines(100), "\n")
	if !strings.Contains(text, "insufficient access rights") || strings.Contains(text, "Доказательства не сохранены") {
		t.Fatalf("LDAP diagnostic hidden: %s", text)
	}
}
