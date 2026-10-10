package tui

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/charmbracelet/x/ansi"
	"wscan/internal/domain"
)

type smbFindingShare struct {
	Name  string
	Read  *bool
	Write *bool
}

// Saved extractors may wrap JSON in "dsl:" and append credentials. Decode one
// JSON value rather than requiring the entire evidence string to be JSON.
func parseSMBFindingShares(value string) ([]smbFindingShare, bool) {
	attempts := 0
	for pos, r := range value {
		if r != '[' {
			continue
		}
		attempts++
		if attempts > 16 {
			return nil, false
		}
		var rows []smbFindingShare
		decoder := json.NewDecoder(strings.NewReader(value[pos:]))
		if decoder.Decode(&rows) != nil || len(rows) == 0 {
			continue
		}
		valid := true
		for _, row := range rows {
			if row.Name == "" || row.Read == nil && row.Write == nil {
				valid = false
				break
			}
		}
		if valid {
			return rows, true
		}
	}
	return nil, false
}

var smbFindingCredentialRE = regexp.MustCompile(`(?:^|;\s*)user=("(?:\\.|[^"\\])*")\s+pass=("(?:\\.|[^"\\])*")`)

func smbFindingTable(f domain.Finding, width int) (string, bool) {
	var shares []smbFindingShare
	var ok bool
	for _, candidate := range []string{f.Response, f.Evidence} {
		if shares, ok = parseSMBFindingShares(candidate); ok {
			break
		}
	}
	if !ok {
		return "", false
	}
	var body strings.Builder
	if match := smbFindingCredentialRE.FindStringSubmatch(f.Evidence); len(match) == 3 {
		user, userErr := strconv.Unquote(match[1])
		password, passErr := strconv.Unquote(match[2])
		if userErr == nil && passErr == nil {
			if user == "" && password == "" {
				body.WriteString("Вход: без имени и пароля\n\n")
			} else {
				body.WriteString("Пользователь: " + smbCredentialValue(user) + "\nПароль: " + smbCredentialValue(password) + "\n\n")
			}
		}
	}
	nameWidth := 4
	for _, share := range shares {
		nameWidth = max(nameWidth, ansi.StringWidth(smbDisplayName(share.Name)))
	}
	nameWidth = min(nameWidth, max(4, width-20))
	pad := func(value string, n int) string {
		return value + strings.Repeat(" ", max(0, n-ansi.StringWidth(value)))
	}
	fmt.Fprintf(&body, "%s  %-7s  %s\n", pad("Шара", nameWidth), "Чтение", "Запись")
	for _, share := range shares {
		name := smbDisplayName(share.Name)
		if strings.EqualFold(share.Name, "IPC$") {
			body.WriteString(pad(name, nameWidth) + "  служебная (RPC)\n")
			continue
		}
		read, write := smbFindingPermission(share.Read), smbFindingPermission(share.Write)
		if ansi.StringWidth(name) > nameWidth {
			body.WriteString(name + "\n" + strings.Repeat(" ", nameWidth))
		} else {
			body.WriteString(pad(name, nameWidth))
		}
		body.WriteString("  " + pad(read, 7) + "  " + write + "\n")
	}
	return strings.TrimSpace(body.String()), true
}

func smbFindingPermission(value *bool) string {
	if value == nil {
		return "?"
	}
	if *value {
		return "да"
	}
	return "нет"
}

func smbCredentialValue(value string) string {
	if value == "" {
		return "(пустой)"
	}
	if strings.Trim(value, " ") == "" {
		return fmt.Sprintf("%d пробел(а)", len([]rune(value)))
	}
	return smbDisplayName(strconv.Quote(value))
}
