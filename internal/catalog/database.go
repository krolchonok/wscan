package catalog

import "wscan/internal/domain"

// DatabaseType refines the database service bucket. Prefer the path/product
// over search text, which may mention unrelated products in tags or references.
func DatabaseType(e Entry) string {
	for _, text := range []string{e.Path, e.Product, e.SearchText} {
		if family := domain.DatabaseFamily(text); family != "" {
			return family
		}
	}
	return "Прочие БД"
}
