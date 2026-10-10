package domain

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func decodeNode(t *testing.T, yml string) *yaml.Node {
	t.Helper()
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(yml), &doc); err != nil {
		t.Fatalf("yaml.Unmarshal: %v", err)
	}
	// top-level document node wraps the actual content node.
	return doc.Content[0]
}

func TestIntListUnmarshalYAML(t *testing.T) {
	cases := []struct {
		name string
		yml  string
		want []int
	}{
		{"plain int", "6379", []int{6379}},
		{"quoted single port", `"6379"`, []int{6379}},
		{"comma list unquoted", "25,2525,465,587", []int{25, 2525, 465, 587}},
		{"comma list quoted", `"6379,6380"`, []int{6379, 6380}},
		{"comma list with spaces", `"21, 2121"`, []int{21, 2121}},
		{"yaml sequence", "[21, 2121]", []int{21, 2121}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var got IntList
			if err := got.UnmarshalYAML(decodeNode(t, c.yml)); err != nil {
				t.Fatalf("unmarshal %q: %v", c.yml, err)
			}
			if len(got) != len(c.want) {
				t.Fatalf("got %v want %v", got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Fatalf("got %v want %v", got, c.want)
				}
			}
		})
	}
}

func TestIntListUnmarshalYAMLNonNumericExpressionFallsBack(t *testing.T) {
	// A template port expression (e.g. "{{Port}}") isn't a literal port list;
	// callers must fall back to the target's own port instead of failing the
	// whole template.
	var got IntList
	if err := got.UnmarshalYAML(decodeNode(t, `"{{Port}}"`)); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got != nil {
		t.Fatalf("got %v want nil (fallback)", got)
	}
}

func TestStringListUnmarshalYAMLScalar(t *testing.T) {
	// info.reference accepts either one string or a list in nuclei templates.
	var got StringList
	if err := got.UnmarshalYAML(decodeNode(t, "https://example.com/advisory")); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got) != 1 || got[0] != "https://example.com/advisory" {
		t.Fatalf("got %v", got)
	}
}

func TestStringListUnmarshalYAMLList(t *testing.T) {
	var got StringList
	if err := got.UnmarshalYAML(decodeNode(t, "[https://a.example, https://b.example]")); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %v", got)
	}
}
