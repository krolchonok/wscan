package engine

import (
	"strings"

	"github.com/antchfx/htmlquery"
)

// xpathQuery runs an XPath 1.0 expression against HTML and returns matching
// node text (or the named attribute). XPath 2.0 helpers like matches() are not
// supported by the underlying library and yield no hits.
func xpathQuery(hay, expr, attr string) []string {
	doc, err := htmlquery.Parse(strings.NewReader(hay))
	if err != nil || doc == nil {
		return nil
	}
	nodes, err := htmlquery.QueryAll(doc, expr)
	if err != nil || len(nodes) == 0 {
		return nil
	}
	out := make([]string, 0, len(nodes))
	for _, n := range nodes {
		if attr != "" {
			if v := htmlquery.SelectAttr(n, attr); v != "" {
				out = append(out, v)
			}
			continue
		}
		if s := strings.TrimSpace(htmlquery.InnerText(n)); s != "" {
			out = append(out, s)
		} else if s := htmlquery.OutputHTML(n, true); s != "" {
			out = append(out, s)
		}
	}
	return out
}
