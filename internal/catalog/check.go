package catalog

import (
	"strings"

	"wscan/internal/nse"
	tpl "wscan/internal/template"
)

// Check is an offline compatibility check against our own native engine. For
// NSE it checks only loading/imports; request execution and Lua action APIs
// still depend on the selected target. For nuclei-format templates it parses
// natively and reports the features the native engine does not support.
func Check(source []byte, path string) (bool, string) {
	return CheckWithLibrary(source, path, "")
}

// CheckWithLibrary is Check with an explicit NSE library directory so nselib
// modules (smb, brute, …) resolve during catalog compatibility checks.
func CheckWithLibrary(source []byte, path, libraryDir string) (bool, string) {
	if strings.HasPrefix(path, "nmap/scripts/") {
		if err := nse.CheckSource(source, libraryDir); err != nil {
			return false, err.Error()
		}
		return true, ""
	}
	t, err := tpl.ForExecution(source, path)
	if err != nil {
		return false, err.Error()
	}
	if !t.Compatible {
		return false, strings.Join(t.Unsupported, "; ")
	}
	return true, ""
}
