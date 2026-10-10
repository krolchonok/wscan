package nse

import (
	"unicode/utf8"

	lua "github.com/yuin/gopher-lua"
)

func registerUTF8(L *lua.LState) {
	mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
		"char":      utf8Char,
		"len":       utf8Len,
		"offset":    utf8Offset,
		"codepoint": utf8Codepoint,
		"codes":     utf8Codes,
	})
	L.SetGlobal("utf8", mod)
	L.PreloadModule("utf8", func(L *lua.LState) int {
		L.Push(mod)
		return 1
	})
}

func utf8Char(L *lua.LState) int {
	n := L.GetTop()
	buf := make([]byte, 0, n*4)
	tmp := make([]byte, utf8.UTFMax)
	for i := 1; i <= n; i++ {
		r := rune(L.CheckInt(i))
		m := utf8.EncodeRune(tmp, r)
		buf = append(buf, tmp[:m]...)
	}
	L.Push(lua.LString(string(buf)))
	return 1
}

func utf8Len(L *lua.LState) int {
	s := L.CheckString(1)
	L.Push(lua.LNumber(utf8.RuneCountInString(s)))
	return 1
}

func utf8Offset(L *lua.LState) int {
	s := L.CheckString(1)
	n := L.CheckInt(2)
	i := 1
	if L.GetTop() >= 3 {
		i = L.CheckInt(3)
	}
	if i < 1 {
		i = 1
	}
	b := []byte(s)
	pos := i - 1
	if n == 0 {
		L.Push(lua.LNumber(i))
		return 1
	}
	if n > 0 {
		for n > 0 && pos < len(b) {
			_, size := utf8.DecodeRune(b[pos:])
			pos += size
			n--
		}
		if n > 0 {
			L.Push(lua.LNil)
			return 1
		}
		L.Push(lua.LNumber(pos + 1))
		return 1
	}
	// n < 0: step backwards from i
	for n < 0 && pos > 0 {
		_, size := utf8.DecodeLastRune(b[:pos])
		pos -= size
		n++
	}
	if n < 0 {
		L.Push(lua.LNil)
		return 1
	}
	L.Push(lua.LNumber(pos + 1))
	return 1
}

func utf8Codepoint(L *lua.LState) int {
	s := L.CheckString(1)
	i := 1
	j := i
	if L.GetTop() >= 2 {
		i = L.CheckInt(2)
		j = i
	}
	if L.GetTop() >= 3 {
		j = L.CheckInt(3)
	}
	b := []byte(s)
	pos := 0
	idx := 1
	for pos < len(b) && idx < i {
		_, size := utf8.DecodeRune(b[pos:])
		pos += size
		idx++
	}
	nret := 0
	for pos < len(b) && idx <= j {
		r, size := utf8.DecodeRune(b[pos:])
		L.Push(lua.LNumber(r))
		nret++
		pos += size
		idx++
	}
	return nret
}

func utf8Codes(L *lua.LState) int {
	s := L.CheckString(1)
	b := []byte(s)
	iter := L.NewFunction(func(L *lua.LState) int {
		pos := L.CheckInt(2) // byte offset after last rune (0-based stored as number)
		if pos < 0 || pos >= len(b) {
			return 0
		}
		r, size := utf8.DecodeRune(b[pos:])
		L.Push(lua.LNumber(pos + size))
		L.Push(lua.LNumber(r))
		return 2
	})
	L.Push(iter)
	L.Push(lua.LNil)
	L.Push(lua.LNumber(0))
	return 3
}
