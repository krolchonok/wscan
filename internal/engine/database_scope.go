package engine

import (
	"net/url"
	"strconv"
	"strings"

	"wscan/internal/domain"
)

// databaseTemplateMatches prevents a check for one DB from being dispatched
// against a different discovered DB, including mixed bulk-port scans.
func databaseTemplateMatches(t domain.Template, target string, services []domain.Service) bool {
	family := ""
	for _, text := range []string{t.Source, t.ID, t.Info.Name, t.Info.Tags} {
		if family = domain.DatabaseFamily(text); family != "" {
			break
		}
	}
	if family == "" {
		return true
	}
	if !strings.Contains(target, "://") {
		target = "tcp://" + target
	}
	u, err := url.Parse(target)
	if err != nil {
		return true
	}
	port, _ := strconv.Atoi(u.Port())
	for _, s := range services {
		if strings.EqualFold(s.Host, u.Hostname()) && s.Port == port {
			actual := domain.ServiceDatabase(s)
			return actual == "" || actual == family
		}
	}
	return true
}
