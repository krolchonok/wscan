package engine

import (
	"context"
	"strings"
	"testing"

	"wscan/internal/domain"
)

// TestPassedExprsNamesOnlyTheExpressionsThatFired reproduces the TUI
// complaint that a dsl/xpath match's evidence was the fixed, useless string
// "dsl matched" (no matter which expression fired, or how many). For an
// "or" condition, only the expressions that actually evaluated true should
// be named — naming the whole list would falsely imply every expression
// passed.
func TestPassedExprsNamesOnlyTheExpressionsThatFired(t *testing.T) {
	exprs := []string{"a == 1", "b == 2", "c == 3"}
	checks := []bool{false, true, false}
	got := passedExprs(exprs, checks)
	if len(got) != 1 || got[0] != "b == 2" {
		t.Fatalf("got %v, want only [\"b == 2\"]", got)
	}
}

// TestJSFindingEvidenceIncludesDSLExprAndResponse reproduces the real-world
// complaint: rdp-detect.yaml's finding showed only "Доказательства: dsl
// matched" in the TUI — no indication of which condition fired or what the
// script actually found (the OS string), unless the user pressed "r" to
// reveal the raw response. The evidence should name the DSL condition AND
// fold in a short rendering of the script's own response, since for a
// javascript: template without extractors that response IS the finding.
func TestJSFindingEvidenceIncludesDSLExprAndResponse(t *testing.T) {
	tmpl := domain.Template{
		ID: "synthetic-detect", Compatible: true, Risk: "active",
		Info: struct {
			Name        string            `yaml:"name"`
			Severity    string            `yaml:"severity"`
			Tags        string            `yaml:"tags"`
			Description string            `yaml:"description"`
			Reference   domain.StringList `yaml:"reference"`
		}{Name: "synthetic-detect", Severity: "info"},
		JavaScript: []domain.JavaScriptRequest{{
			Code: `Export({IsRDP: true, OS: "Windows Server 2016 or 2019"});`,
			Args: map[string]any{"Host": "127.0.0.1", "Port": "0"},
			Matchers: []domain.Matcher{{
				Type: "dsl",
				DSL:  []string{`contains(response, "IsRDP")`},
			}},
		}},
	}
	e := New(nil, Config{TimeoutSeconds: 5})
	fs, errs := e.execTemplate(context.Background(), tmpl, "127.0.0.1:0", execContext{timeout: 5})
	if len(errs) > 0 {
		t.Fatalf("errs=%v", errs)
	}
	if len(fs) != 1 {
		t.Fatalf("findings=%v", fs)
	}
	ev := fs[0].Evidence
	if !strings.Contains(ev, `contains(response, "IsRDP")`) {
		t.Errorf("evidence must name the DSL condition that fired, got %q", ev)
	}
	if !strings.Contains(ev, "Windows Server 2016 or 2019") {
		t.Errorf("evidence must fold in the script's own response, got %q", ev)
	}
	if ev == "dsl matched" {
		t.Fatal("evidence must not be the old, uninformative fixed string")
	}
}
