package tui

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var mysqlAliasIdentifier = regexp.MustCompile(`^[\p{L}_][\p{L}\p{N}_$]*$`)

func mysqlReadAlias(input string) (query string, alias bool, err error) {
	fields := strings.Fields(input)
	if len(fields) == 0 || !strings.HasPrefix(fields[0], ":") {
		return "", false, nil
	}
	command := strings.ToLower(fields[0])
	if len(fields) == 1 {
		switch command {
		case ":db":
			return "SELECT DATABASE(), CURRENT_USER()", true, nil
		case ":tables":
			return "SELECT TABLE_SCHEMA, TABLE_NAME, TABLE_TYPE FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA=DATABASE() ORDER BY TABLE_NAME", true, nil
		}
	}
	switch command {
	case ":rows", ":columns", ":count":
		if len(fields) < 2 || len(fields) > 3 || (command != ":rows" && len(fields) != 2) {
			break
		}
		parts := strings.Split(fields[1], ".")
		if len(parts) > 2 {
			return "", true, fmt.Errorf("укажи table или database.table")
		}
		for _, p := range parts {
			if !mysqlAliasIdentifier.MatchString(p) {
				return "", true, fmt.Errorf("укажи table или database.table без SQL")
			}
		}
		quoted := make([]string, len(parts))
		for i, p := range parts {
			quoted[i] = "`" + p + "`"
		}
		table := strings.Join(quoted, ".")
		switch command {
		case ":rows":
			limit := 100
			if len(fields) == 3 {
				limit, err = strconv.Atoi(fields[2])
				if err != nil || limit < 1 || limit > 500 {
					return "", true, fmt.Errorf("число строк: от 1 до 500")
				}
			}
			return fmt.Sprintf("SELECT * FROM %s LIMIT %d", table, limit), true, nil
		case ":count":
			return "SELECT COUNT(*) AS row_count FROM " + table, true, nil
		case ":columns":
			schema := "DATABASE()"
			if len(parts) == 2 {
				schema = "'" + parts[0] + "'"
			}
			return "SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE, COLUMN_DEFAULT FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=" + schema + " AND TABLE_NAME='" + parts[len(parts)-1] + "' ORDER BY ORDINAL_POSITION", true, nil
		}
	}
	return "", true, fmt.Errorf("алиасы: :db · :tables · :columns table · :rows table [1–500] · :count table")
}
