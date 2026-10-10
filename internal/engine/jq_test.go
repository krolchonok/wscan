package engine

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestJQEval(t *testing.T) {
	cases := []struct{ doc, path, want string }{
		{`{"version":"1.2"}`, ".version?", "1.2"},
		{`{"status":["a","b","c"]}`, ".status[]", "a,b,c"},
		{`{"applinks":{"details":[{"appID":"X"},{"appID":"Y"}]}}`, ".applinks.details[].appID", "X,Y"},
		{`{"events":[{"eventAction":"registration","eventDate":"2020"},{"eventAction":"expiration","eventDate":"2030"}]}`,
			`.events[] | select(.eventAction == "registration").eventDate`, "2020"},
		{`{"a":{"b":5}}`, ".a.b", "5"},
		{`{"a":"x"}`, ".missing?", ""},
	}
	for _, c := range cases {
		var d any
		_ = json.Unmarshal([]byte(c.doc), &d)
		if got := strings.Join(jqEval(d, c.path), ","); got != c.want {
			t.Errorf("jq %q on %s = %q, want %q", c.path, c.doc, got, c.want)
		}
	}
}
