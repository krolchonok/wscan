package js

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestRequireUnsupportedModuleReturnsRealError(t *testing.T) {
	for _, name := range []string{"oracle", "rsync", "smtp"} {
		result := Run(context.Background(), `require("nuclei/`+name+`"); true;`, "", nil, nil, "", time.Second)
		if result.Success || !strings.Contains(result.Error, "not implemented") {
			t.Fatalf("%s: %+v", name, result)
		}
	}
}
