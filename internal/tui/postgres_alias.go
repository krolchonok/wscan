package tui

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var pgAliasIdentifier = regexp.MustCompile(`^[\p{L}_][\p{L}\p{N}_@$#]*$`)

// Aliases only generate fixed read queries in the current database.
func pgReadAlias(input string) (query string, alias bool, err error) {
	fields := strings.Fields(input)
	if len(fields) == 0 || !strings.HasPrefix(fields[0], ":") {
		return "", false, nil
	}
	alias = true
	command := strings.ToLower(fields[0])
	switch command {
	case ":db":
		if len(fields) == 1 {
			return "SELECT current_database(), current_user", true, nil
		}
	case ":tables":
		if len(fields) == 1 {
			return "SELECT TABLE_SCHEMA AS schema, TABLE_NAME AS table_name, TABLE_TYPE AS type FROM INFORMATION_SCHEMA.TABLES ORDER BY TABLE_SCHEMA, TABLE_NAME", true, nil
		}
	case ":rows", ":columns", ":count":
		if len(fields) < 2 || len(fields) > 3 || (command != ":rows" && len(fields) != 2) {
			break
		}
		parts := strings.Split(fields[1], ".")
		if len(parts) == 1 {
			parts = append([]string{"public"}, parts...)
		}
		if len(parts) != 2 {
			return "", true, fmt.Errorf("укажи таблицу или schema.table текущей базы")
		}
		for _, p := range parts {
			if !pgAliasIdentifier.MatchString(p) {
				return "", true, fmt.Errorf("имя: schema.table, без SQL; для сложных имён используй SQL-запрос")
			}
		}
		table := `"` + parts[0] + `"."` + parts[1] + `"`
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
			return "SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE, COLUMN_DEFAULT FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA='" + parts[0] + "' AND TABLE_NAME='" + parts[1] + "' ORDER BY ORDINAL_POSITION", true, nil
		}
	}
	return "", true, fmt.Errorf("алиасы: :db · :tables · :columns schema.table · :rows schema.table [1–500] · :count schema.table")
}
