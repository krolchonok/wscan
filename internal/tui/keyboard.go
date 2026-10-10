package tui

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// normalizeShortcut matches Russian ЙЦУКЕН keys to their QWERTY positions.
// The router calls it only outside text input, preserving typed Cyrillic.
func normalizeShortcut(key string) string {
	if utf8.RuneCountInString(key) != 1 {
		return key
	}
	r, _ := utf8.DecodeRuneInString(key)
	const russian = "йцукенгшщзхъфывапролджэячсмитьбюё"
	const english = "qwertyuiop[]asdfghjkl;'zxcvbnm,.`"
	i := strings.IndexRune(russian, unicode.ToLower(r))
	if i < 0 {
		return key
	}
	// IndexRune returns a byte offset; every Russian letter above is two bytes.
	mapped := rune(english[i/2])
	if unicode.IsUpper(r) {
		mapped = unicode.ToUpper(mapped)
	}
	return string(mapped)
}
