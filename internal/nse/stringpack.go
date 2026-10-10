package nse

import (
	"encoding/binary"
	"fmt"
	"math"

	lua "github.com/yuin/gopher-lua"
)

// registerStringPack adds Lua 5.3-compatible string.pack / string.unpack.
func registerStringPack(L *lua.LState) {
	str, ok := L.GetGlobal("string").(*lua.LTable)
	if !ok {
		return
	}
	L.SetField(str, "pack", L.NewFunction(luaStringPack))
	L.SetField(str, "unpack", L.NewFunction(luaStringUnpack))
	L.SetField(str, "packsize", L.NewFunction(luaStringPackSize))
}

func registerBitLib(L *lua.LState) {
	mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
		"band":    bitBand,
		"bor":     bitBor,
		"bxor":    bitBxor,
		"bnot":    bitBnot,
		"lshift":  bitLshift,
		"rshift":  bitRshift,
		"arshift": bitRshift,
		"idiv":    bitIdiv,
	})
	L.SetGlobal("bit", mod)
	L.PreloadModule("bit", func(L *lua.LState) int { L.Push(mod); return 1 })
	L.PreloadModule("bit32", func(L *lua.LState) int { L.Push(mod); return 1 })
}

func bitArgs(L *lua.LState) (uint64, uint64) {
	return uint64(int64(L.CheckNumber(1))), uint64(int64(L.CheckNumber(2)))
}

func bitBand(L *lua.LState) int { a, b := bitArgs(L); L.Push(lua.LNumber(int64(a & b))); return 1 }
func bitBor(L *lua.LState) int  { a, b := bitArgs(L); L.Push(lua.LNumber(int64(a | b))); return 1 }
func bitBxor(L *lua.LState) int { a, b := bitArgs(L); L.Push(lua.LNumber(int64(a ^ b))); return 1 }
func bitBnot(L *lua.LState) int {
	a := uint64(int64(L.CheckNumber(1)))
	L.Push(lua.LNumber(int64(^a)))
	return 1
}
func bitLshift(L *lua.LState) int {
	a, b := bitArgs(L)
	L.Push(lua.LNumber(int64(a << (b & 63))))
	return 1
}
func bitRshift(L *lua.LState) int {
	a, b := bitArgs(L)
	L.Push(lua.LNumber(int64(a >> (b & 63))))
	return 1
}
func bitIdiv(L *lua.LState) int {
	a := float64(L.CheckNumber(1))
	b := float64(L.CheckNumber(2))
	L.Push(lua.LNumber(math.Floor(a / b)))
	return 1
}

func registerMathToInteger(L *lua.LState) {
	mathT, ok := L.GetGlobal("math").(*lua.LTable)
	if !ok {
		return
	}
	L.SetField(mathT, "tointeger", L.NewFunction(func(L *lua.LState) int {
		v := L.Get(1)
		switch n := v.(type) {
		case lua.LNumber:
			L.Push(lua.LNumber(int64(n)))
			return 1
		case lua.LString:
			var x int64
			if _, err := fmt.Sscan(string(n), &x); err == nil {
				L.Push(lua.LNumber(x))
				return 1
			}
		}
		L.Push(lua.LNil)
		return 1
	}))
}

// registerTableUnpack aliases Lua 5.2+ table.unpack to the 5.1 global unpack.
func registerTableUnpack(L *lua.LState) {
	tbl, ok := L.GetGlobal("table").(*lua.LTable)
	if !ok {
		return
	}
	if L.GetField(tbl, "unpack") != lua.LNil {
		return
	}
	L.SetField(tbl, "unpack", L.GetGlobal("unpack"))
}

type packCursor struct {
	endian binary.ByteOrder
	buf    []byte
	out    []byte
	pos    int // 1-based for unpack return
}

func luaStringPack(L *lua.LState) int {
	fmtStr := L.CheckString(1)
	args := make([]lua.LValue, L.GetTop()-1)
	for i := range args {
		args[i] = L.Get(i + 2)
	}
	out, err := stringPack(fmtStr, args)
	if err != nil {
		L.RaiseError("%v", err)
		return 0
	}
	L.Push(lua.LString(out))
	return 1
}

func luaStringUnpack(L *lua.LState) int {
	fmtStr := L.CheckString(1)
	data := L.CheckString(2)
	pos := 1
	if L.GetTop() >= 3 {
		pos = L.CheckInt(3)
	}
	vals, next, err := stringUnpack(fmtStr, []byte(data), pos)
	if err != nil {
		L.RaiseError("%v", err)
		return 0
	}
	for _, v := range vals {
		L.Push(v)
	}
	L.Push(lua.LNumber(next))
	return len(vals) + 1
}

func luaStringPackSize(L *lua.LState) int {
	n, err := stringPackSize(L.CheckString(1))
	if err != nil {
		L.RaiseError("%v", err)
		return 0
	}
	L.Push(lua.LNumber(n))
	return 1
}

func stringPackSize(format string) (int, error) {
	size := 0
	for i := 0; i < len(format); {
		ch := format[i]
		i++
		switch ch {
		case ' ', '\t', '\n', '\r', '<', '>', '!', '=':
			continue
		case 'x', 'B', 'b', 'C':
			size++
		case 'c':
			n, ni := parsePackWidth(format, i, 1)
			i = ni
			size += n
		case 's', 'z':
			return 0, fmt.Errorf("string.packsize: variable-length format")
		case 'H', 'h', 'I', 'i', 'L', 'l', 'T', 'J', 'j':
			isz, _ := intSize(ch)
			n, ni := parsePackWidth(format, i, isz)
			i = ni
			size += n
		case 'f':
			size += 4
		case 'd', 'n':
			size += 8
		default:
			return 0, fmt.Errorf("string.packsize: unsupported option %q", string(ch))
		}
	}
	return size, nil
}

func stringPack(format string, args []lua.LValue) (string, error) {
	c := &packCursor{endian: binary.BigEndian}
	ai := 0
	for i := 0; i < len(format); {
		ch := format[i]
		i++
		switch ch {
		case ' ', '\t', '\n', '\r':
			continue
		case '<':
			c.endian = binary.LittleEndian
		case '>', '!':
			c.endian = binary.BigEndian
		case '=':
			c.endian = binary.LittleEndian
		case 'x':
			c.out = append(c.out, 0)
		case 'z':
			if ai >= len(args) {
				return "", fmt.Errorf("string.pack: missing arg for z")
			}
			s := lua.LVAsString(args[ai])
			ai++
			c.out = append(c.out, []byte(s)...)
			c.out = append(c.out, 0)
		case 'c':
			n, ni := parsePackWidth(format, i, 1)
			i = ni
			if ai >= len(args) {
				return "", fmt.Errorf("string.pack: missing arg for c")
			}
			s := lua.LVAsString(args[ai])
			ai++
			b := []byte(s)
			if len(b) > n {
				b = b[:n]
			}
			c.out = append(c.out, b...)
			for len(b) < n {
				c.out = append(c.out, 0)
				b = append(b, 0)
			}
		case 's':
			n, ni := parsePackWidth(format, i, 0)
			i = ni
			if n == 0 {
				n = 1
			}
			if ai >= len(args) {
				return "", fmt.Errorf("string.pack: missing arg for s")
			}
			s := lua.LVAsString(args[ai])
			ai++
			b := []byte(s)
			lenBuf := make([]byte, n)
			switch n {
			case 1:
				lenBuf[0] = byte(len(b))
			case 2:
				c.endian.PutUint16(lenBuf, uint16(len(b)))
			case 4:
				c.endian.PutUint32(lenBuf, uint32(len(b)))
			case 8:
				c.endian.PutUint64(lenBuf, uint64(len(b)))
			default:
				return "", fmt.Errorf("string.pack: bad s width %d", n)
			}
			c.out = append(c.out, lenBuf...)
			c.out = append(c.out, b...)
		case 'B', 'b', 'C':
			if ai >= len(args) {
				return "", fmt.Errorf("string.pack: missing integer arg")
			}
			v := uint64(luaNum(args[ai]))
			ai++
			c.out = append(c.out, byte(v))
		case 'H', 'h', 'I', 'i', 'L', 'l', 'T', 'J', 'j':
			size, signed := intSize(ch)
			n, ni := parsePackWidth(format, i, size)
			i = ni
			if ai >= len(args) {
				return "", fmt.Errorf("string.pack: missing integer arg")
			}
			v := luaNum(args[ai])
			ai++
			c.out = append(c.out, putInt(c.endian, n, signed, v)...)
		case 'f':
			if ai >= len(args) {
				return "", fmt.Errorf("string.pack: missing float arg")
			}
			var buf [4]byte
			c.endian.PutUint32(buf[:], math.Float32bits(float32(luaNum(args[ai]))))
			ai++
			c.out = append(c.out, buf[:]...)
		case 'd', 'n':
			if ai >= len(args) {
				return "", fmt.Errorf("string.pack: missing double arg")
			}
			var buf [8]byte
			c.endian.PutUint64(buf[:], math.Float64bits(luaNum(args[ai])))
			ai++
			c.out = append(c.out, buf[:]...)
		default:
			return "", fmt.Errorf("string.pack: unsupported option %q", string(ch))
		}
	}
	return string(c.out), nil
}

func stringUnpack(format string, data []byte, pos1based int) ([]lua.LValue, int, error) {
	c := &packCursor{endian: binary.BigEndian, buf: data, pos: pos1based}
	if c.pos < 1 {
		c.pos = 1
	}
	var vals []lua.LValue
	for i := 0; i < len(format); {
		ch := format[i]
		i++
		switch ch {
		case ' ', '\t', '\n', '\r':
			continue
		case '<':
			c.endian = binary.LittleEndian
		case '>', '!':
			c.endian = binary.BigEndian
		case '=':
			c.endian = binary.LittleEndian
		case 'x':
			c.pos++
		case 'z':
			start := c.pos - 1
			if start < 0 || start >= len(c.buf) {
				return nil, c.pos, fmt.Errorf("string.unpack: short z")
			}
			end := start
			for end < len(c.buf) && c.buf[end] != 0 {
				end++
			}
			vals = append(vals, lua.LString(c.buf[start:end]))
			c.pos = end + 2 // past NUL, 1-based next
		case 'c':
			n, ni := parsePackWidth(format, i, 1)
			i = ni
			start := c.pos - 1
			if start+n > len(c.buf) {
				return nil, c.pos, fmt.Errorf("string.unpack: short c")
			}
			vals = append(vals, lua.LString(c.buf[start:start+n]))
			c.pos += n
		case 's':
			n, ni := parsePackWidth(format, i, 0)
			i = ni
			if n == 0 {
				n = 1
			}
			start := c.pos - 1
			if start+n > len(c.buf) {
				return nil, c.pos, fmt.Errorf("string.unpack: short s len")
			}
			var strlen int
			switch n {
			case 1:
				strlen = int(c.buf[start])
			case 2:
				strlen = int(c.endian.Uint16(c.buf[start:]))
			case 4:
				strlen = int(c.endian.Uint32(c.buf[start:]))
			case 8:
				strlen = int(c.endian.Uint64(c.buf[start:]))
			}
			start += n
			if start+strlen > len(c.buf) {
				return nil, c.pos, fmt.Errorf("string.unpack: short s data")
			}
			vals = append(vals, lua.LString(c.buf[start:start+strlen]))
			c.pos = start + strlen + 1
		case 'B', 'b', 'C':
			start := c.pos - 1
			if start >= len(c.buf) {
				return nil, c.pos, fmt.Errorf("string.unpack: short byte")
			}
			vals = append(vals, lua.LNumber(c.buf[start]))
			c.pos++
		case 'H', 'h', 'I', 'i', 'L', 'l', 'T', 'J', 'j':
			size, signed := intSize(ch)
			n, ni := parsePackWidth(format, i, size)
			i = ni
			start := c.pos - 1
			if start+n > len(c.buf) {
				return nil, c.pos, fmt.Errorf("string.unpack: short int")
			}
			vals = append(vals, lua.LNumber(getInt(c.endian, c.buf[start:start+n], signed)))
			c.pos += n
		case 'f':
			start := c.pos - 1
			if start+4 > len(c.buf) {
				return nil, c.pos, fmt.Errorf("string.unpack: short float")
			}
			vals = append(vals, lua.LNumber(math.Float32frombits(c.endian.Uint32(c.buf[start:]))))
			c.pos += 4
		case 'd', 'n':
			start := c.pos - 1
			if start+8 > len(c.buf) {
				return nil, c.pos, fmt.Errorf("string.unpack: short double")
			}
			vals = append(vals, lua.LNumber(math.Float64frombits(c.endian.Uint64(c.buf[start:]))))
			c.pos += 8
		default:
			return nil, c.pos, fmt.Errorf("string.unpack: unsupported option %q", string(ch))
		}
	}
	return vals, c.pos, nil
}

func parsePackWidth(format string, i, def int) (int, int) {
	if i >= len(format) || format[i] < '0' || format[i] > '9' {
		return def, i
	}
	n := 0
	for i < len(format) && format[i] >= '0' && format[i] <= '9' {
		n = n*10 + int(format[i]-'0')
		i++
	}
	// Explicit width 0 is valid for 'c' (empty string); only fall back to
	// default when no digits were present (handled above).
	return n, i
}

func intSize(ch byte) (int, bool) {
	switch ch {
	case 'b':
		return 1, true
	case 'B', 'C':
		return 1, false
	case 'h':
		return 2, true
	case 'H':
		return 2, false
	case 'i':
		return 4, true
	case 'I', 'T':
		return 4, false
	case 'l', 'j':
		return 8, true
	case 'L', 'J':
		return 8, false
	}
	return 4, false
}

func luaNum(v lua.LValue) float64 {
	switch n := v.(type) {
	case lua.LNumber:
		return float64(n)
	case lua.LString:
		var x float64
		fmt.Sscan(string(n), &x)
		return x
	default:
		return 0
	}
}

func putInt(order binary.ByteOrder, n int, signed bool, v float64) []byte {
	buf := make([]byte, n)
	iv := int64(v)
	uv := uint64(v)
	switch n {
	case 1:
		buf[0] = byte(uv)
	case 2:
		if signed {
			order.PutUint16(buf, uint16(int16(iv)))
		} else {
			order.PutUint16(buf, uint16(uv))
		}
	case 4:
		if signed {
			order.PutUint32(buf, uint32(int32(iv)))
		} else {
			order.PutUint32(buf, uint32(uv))
		}
	case 8:
		if signed {
			order.PutUint64(buf, uint64(iv))
		} else {
			order.PutUint64(buf, uv)
		}
	}
	return buf
}

func getInt(order binary.ByteOrder, b []byte, signed bool) float64 {
	switch len(b) {
	case 1:
		if signed {
			return float64(int8(b[0]))
		}
		return float64(b[0])
	case 2:
		v := order.Uint16(b)
		if signed {
			return float64(int16(v))
		}
		return float64(v)
	case 4:
		v := order.Uint32(b)
		if signed {
			return float64(int32(v))
		}
		return float64(v)
	case 8:
		v := order.Uint64(b)
		if signed {
			return float64(int64(v))
		}
		return float64(v)
	}
	return 0
}
