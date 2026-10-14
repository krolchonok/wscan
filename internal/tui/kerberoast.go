package tui

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"
	"wscan/internal/adscan"
)

// Keep the selected Kerberos form visible without the full AD action list
// pushing its fields below the panel on short terminals.
func (m model) viewKerberoastSetup(w int) string {
	modes := []string{"Пароль / NT-хеш", "Без пароля: учётка без pre-auth", "Готовый TGT"}
	rows := []string{
		"h Контроллер: " + valueOr(m.adAccessHost, "не задан"),
		"d Домен: " + valueOr(m.adAccessDomain, "не задан"),
		"a Режим: " + modes[m.adKerberoastAuth],
	}
	switch m.adKerberoastAuth {
	case 0:
		cred := "выбери сохранённую учётку"
		if m.adAccessCred >= 0 && m.adAccessCred < len(m.adAccessCreds) {
			cred = credIdentLabel(m.adAccessCreds[m.adAccessCred])
		}
		rows = append(rows, "c Учётка: "+cred)
	case 1:
		rows = append(rows, "u Логин без pre-auth: "+valueOr(m.adKerberoastNoPreauthUser, "не задан"))
	case 2:
		rows = append(rows, "t Файл TGT: "+valueOr(m.adKerberoastTGTFile, ".kirbi / .ccache v3/v4"))
	}
	spns := "автоматически из LDAP"
	if m.adKerberoastAuth != 0 {
		spns = "укажи SPN или @файл"
	}
	rows = append(rows, "s SPN: "+valueOr(m.adKerberoastSPNs, spns))
	auto := "Авто: AES → RC4"
	if m.adKerberoastAuth == 1 {
		auto = "Авто: RC4 → AES"
	}
	rows = append(rows, "e Шифрование: "+[]string{auto, "Только RC4", "Только AES"}[m.adKerberoastEtypes])
	if m.adKerberoastAuth == 0 {
		rows = append(rows, fmt.Sprintf("l LDAP-порт: %d", m.adAccessLDAPPort))
	} else {
		rows = append(rows, "Для AES: SPN|логин владельца; RC4 — SPN")
	}
	body := headingStyle.Render("Kerberoasting") + "\n\n"
	for _, row := range rows {
		body += renderListRow(row, false, w-4)
	}
	body += "\nEnter запуск · ↑/↓ другая AD-проверка · Esc назад\n"
	if m.adAccessJobRunning() {
		body += "Проверка выполняется… Esc отменить"
	} else if m.height >= 28 {
		body += "Результаты: exports/kerberoast/project-ID/\n"
	}
	return m.renderPanel(w, body)
}

func (m model) kerberoastOptions() (adscan.AccessOptions, error) {
	o := adscan.AccessOptions{Mode: "kerberoast", Host: strings.TrimSpace(m.adAccessHost), Domain: strings.TrimSpace(m.adAccessDomain), LDAPPort: m.adAccessLDAPPort, MaxObjects: 5000, RPS: 2, Timeout: 5 * time.Second, ExportDir: filepath.Join(m.appDir, "exports", "kerberoast", fmt.Sprintf("project-%d", m.current.ID))}
	if o.LDAPPort != 389 && o.LDAPPort != 636 {
		o.LDAPPort = 636
	}
	var err error
	o.SPNs, err = adscan.ReadKerberosList(m.adKerberoastSPNs, o.MaxObjects)
	if err != nil {
		return o, err
	}
	switch m.adKerberoastAuth {
	case 0:
		if m.adAccessCred >= 0 && m.adAccessCred < len(m.adAccessCreds) {
			o.Credential = m.adAccessCreds[m.adAccessCred]
		} else {
			return o, fmt.Errorf("выбери доменную учётку (c) или другой режим (a)")
		}
	case 1:
		o.NoPreauthUser = strings.TrimSpace(m.adKerberoastNoPreauthUser)
		if o.NoPreauthUser == "" {
			return o, fmt.Errorf("укажи логин учётки без pre-auth (u)")
		}
	case 2:
		o.TGTFile = strings.TrimSpace(m.adKerberoastTGTFile)
		if o.TGTFile == "" {
			return o, fmt.Errorf("укажи файл TGT (t)")
		}
	default:
		return o, fmt.Errorf("неизвестный режим Kerberoasting")
	}
	switch m.adKerberoastEtypes {
	case 0:
	case 1:
		o.TGSEtypes = []int32{23}
	case 2:
		o.TGSEtypes = []int32{18, 17}
	default:
		return o, fmt.Errorf("неизвестный режим шифрования")
	}
	err = adscan.ValidateKerberoastOptions(&o)
	return o, err
}
