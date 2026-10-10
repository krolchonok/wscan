package js

import (
	"context"
	"testing"
)

func TestPGReadRejectsTransactionControl(t *testing.T) {
	s := &PGSession{}
	for _, q := range []string{"SET transaction_read_only=off", "COMMIT", "DELETE FROM users", "", "UPDATE users SET a=1"} {
		if _, err := s.Read(context.Background(), q); err == nil {
			t.Fatalf("accepted %q", q)
		}
	}
}
