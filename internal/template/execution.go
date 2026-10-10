package template

import (
	"fmt"

	"wscan/internal/domain"
)

// ForExecution prepares a template for the native engine. This project runs on
// its own engine only (no dependency on the external Nuclei binary), so the
// template is always parsed natively; features the native engine does not
// support mark it incompatible and it is skipped with a clear reason rather
// than handed to an external tool.
func ForExecution(data []byte, source string) (domain.Template, error) {
	if reason := LocalTemplateReason(data, source); reason != "" {
		return domain.Template{}, fmt.Errorf("%s", reason)
	}
	return Parse(data, source)
}
