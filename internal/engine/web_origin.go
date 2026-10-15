package engine

import (
	"net/url"
	"strings"
)

// sameWebOrigin keeps active form and upload probes within the exact origin
// selected by the operator. A page controlled by the target must not be able
// to redirect intrusive requests at another host, port, or scheme.
func sameWebOrigin(base, candidate *url.URL) bool {
	if base == nil || candidate == nil {
		return false
	}
	return strings.EqualFold(base.Scheme, candidate.Scheme) && strings.EqualFold(base.Host, candidate.Host)
}
