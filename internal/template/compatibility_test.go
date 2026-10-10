package template

import (
	"fmt"
	"strings"
	"testing"
)

func TestUnsupportedJSModulesRejectedBeforeExecution(t *testing.T) {
	for _, module := range []string{"oracle", "rsync", "smtp", "unknown"} {
		source := fmt.Sprintf("id: module-check\njavascript:\n  - code: |\n      require('nuclei/%s');\n    matchers:\n      - type: dsl\n        dsl: ['success == true']\n", module)
		template, err := Parse([]byte(source), "test.yaml")
		if err != nil || template.Compatible || !strings.Contains(strings.Join(template.Unsupported, ";"), "module") {
			t.Fatalf("%s: template=%+v error=%v", module, template, err)
		}
	}
}

func TestHTTPUnsupportedSemanticsAreNotIgnored(t *testing.T) {
	for _, option := range []string{"pre-condition: [{type: dsl, dsl: ['method == \"POST\"']}]", "global-matchers: true", "digest-username: admin", "read-all: true", "req-condition: true", "iterate-all: true"} {
		source := "id: options\nhttp:\n  - path: ['{{BaseURL}}']\n    " + option + "\n    matchers: [{type: status, status: [200]}]\n"
		template, err := Parse([]byte(source), "options.yaml")
		if err != nil || template.Compatible {
			t.Fatalf("%s accepted: %+v %v", option, template, err)
		}
	}
	for _, option := range []string{"disable-path-automerge: true", "global-matchers: false", "read-all: false", "max-request: 1", "redirects: true", "cookie-reuse: true"} {
		source := "id: options\nhttp:\n  - path: ['{{BaseURL}}']\n    " + option + "\n    matchers: [{type: status, status: [200]}]\n"
		template, err := Parse([]byte(source), "options.yaml")
		if err != nil || !template.Compatible {
			t.Fatalf("%s rejected: %+v %v", option, template, err)
		}
	}
}
