package nse

import (
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"math/big"

	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/ripemd160"

	lua "github.com/yuin/gopher-lua"
)

func registerOpenSSL(L *lua.LState) {
	L.PreloadModule("openssl", func(L *lua.LState) int {
		mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			"md4":                opensslMD4,
			"md5":                opensslMD5,
			"sha1":               opensslSHA1,
			"sha256":             opensslSHA256,
			"digest":             opensslDigest,
			"hmac":               opensslHMAC,
			"rand_bytes":         opensslRandBytes,
			"rand_pseudo_bytes":  opensslRandBytes,
			"encrypt":            opensslEncrypt,
			"decrypt":            opensslDecrypt,
			"DES_string_to_key":  opensslDESStringToKey,
			"bignum_bin2bn":      opensslBignumBin2BN,
			"bignum_bn2bin":      opensslBignumBN2Bin,
			"bignum_bn2dec":      opensslBignumBN2Dec,
			"bignum_dec2bn":      opensslBignumDec2BN,
			"bignum_hex2bn":      opensslBignumHex2BN,
			"bignum_mod_exp":     opensslBignumModExp,
			"bignum_pseudo_rand": opensslBignumPseudoRand,
		})
		L.Push(mod)
		return 1
	})
}

func registerUnitTestStub(L *lua.LState) {
	L.PreloadModule("unittest", func(L *lua.LState) int {
		mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			"testing":   func(L *lua.LState) int { L.Push(lua.LFalse); return 1 },
			"TestSuite": func(L *lua.LState) int { L.Push(L.NewTable()); return 1 },
		})
		L.Push(mod)
		return 1
	})
}

func registerLFSStub(L *lua.LState) {
	L.PreloadModule("lfs", func(L *lua.LState) int {
		mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			"attributes": func(L *lua.LState) int { L.Push(lua.LNil); return 1 },
			"currentdir": func(L *lua.LState) int { L.Push(lua.LString(".")); return 1 },
			"dir":        func(L *lua.LState) int { L.Push(lua.LNil); return 1 },
			// get_path_separator was entirely missing — any script calling it
			// at load time (http-fetch.nse builds its request path with it)
			// failed to even load with "attempt to call a non-function object".
			"get_path_separator": func(L *lua.LState) int { L.Push(lua.LString("/")); return 1 },
		})
		L.Push(mod)
		return 1
	})
}

func registerLPegStub(L *lua.LState) {
	L.PreloadModule("lpeg", func(L *lua.LState) int {
		// Stub LPeg: enough for nselib that `require "lpeg"` / build patterns
		// at load time (re.lua, lpeg-utility) to not crash. Matching is a no-op
		// (match → nil). A real LPeg port is a separate piece of work.
		mt := L.NewTypeMetatable("lpeg.pattern")
		patOp := func(L *lua.LState) int {
			p := L.NewTable()
			L.SetMetatable(p, L.GetTypeMetatable("lpeg.pattern"))
			L.Push(p)
			return 1
		}
		for _, op := range []string{"__add", "__sub", "__mul", "__div", "__pow", "__unm", "__mod", "__concat"} {
			L.SetField(mt, op, L.NewFunction(patOp))
		}
		L.SetField(mt, "__tostring", L.NewFunction(func(L *lua.LState) int {
			L.Push(lua.LString("lpeg-stub-pattern"))
			return 1
		}))
		newPat := func(L *lua.LState) int {
			p := L.NewTable()
			L.SetMetatable(p, L.GetTypeMetatable("lpeg.pattern"))
			L.Push(p)
			return 1
		}
		mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			"P":     newPat,
			"S":     newPat,
			"R":     newPat,
			"V":     newPat,
			"C":     newPat,
			"Ct":    newPat,
			"Cs":    newPat,
			"Cf":    newPat,
			"Cg":    newPat,
			"Cp":    newPat,
			"Cc":    newPat,
			"Cb":    newPat,
			"Cmt":   newPat,
			"B":     newPat,
			"Carg":  newPat,
			"match": func(L *lua.LState) int { L.Push(lua.LNil); return 1 },
			"locale": func(L *lua.LState) int {
				t := L.OptTable(1, nil)
				if t == nil {
					t = L.NewTable()
				}
				for _, name := range []string{
					"alnum", "alpha", "cntrl", "digit", "graph", "lower",
					"punct", "space", "upper", "xdigit", "print",
				} {
					p := L.NewTable()
					L.SetMetatable(p, L.GetTypeMetatable("lpeg.pattern"))
					t.RawSetString(name, p)
				}
				L.Push(t)
				return 1
			},
			"version": func(L *lua.LState) int { L.Push(lua.LString("lpeg-stub")); return 1 },
		})
		L.Push(mod)
		return 1
	})
}

func registerNmapDBStub(L *lua.LState) {
	L.PreloadModule("nmapdb", func(L *lua.LState) int {
		mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			"get_services": func(L *lua.LState) int { L.Push(L.NewTable()); return 1 },
		})
		L.Push(mod)
		return 1
	})
}

func registerLibSSH2Stub(L *lua.LState) {
	L.PreloadModule("libssh2", func(L *lua.LState) int {
		mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			"session_open": func(L *lua.LState) int { L.Push(lua.LNil); L.Push(lua.LString("libssh2 stub")); return 2 },
		})
		L.Push(mod)
		return 1
	})
}

func opensslHash(data string, h hash.Hash) string {
	h.Write([]byte(data))
	return string(h.Sum(nil))
}

func opensslMD4(L *lua.LState) int {
	L.Push(lua.LString(opensslHash(L.CheckString(1), md4.New())))
	return 1
}
func opensslMD5(L *lua.LState) int {
	L.Push(lua.LString(opensslHash(L.CheckString(1), md5.New())))
	return 1
}
func opensslSHA1(L *lua.LState) int {
	L.Push(lua.LString(opensslHash(L.CheckString(1), sha1.New())))
	return 1
}
func opensslSHA256(L *lua.LState) int {
	L.Push(lua.LString(opensslHash(L.CheckString(1), sha256.New())))
	return 1
}

func opensslDigest(L *lua.LState) int {
	algo := stringsToLower(L.CheckString(1))
	data := L.CheckString(2)
	var h hash.Hash
	switch algo {
	case "md4":
		h = md4.New()
	case "md5":
		h = md5.New()
	case "sha1":
		h = sha1.New()
	case "sha256":
		h = sha256.New()
	case "sha512":
		h = sha512.New()
	case "ripemd160":
		h = ripemd160.New()
	default:
		L.Push(lua.LNil)
		return 1
	}
	L.Push(lua.LString(opensslHash(data, h)))
	return 1
}

func opensslHMAC(L *lua.LState) int {
	algo := stringsToLower(L.CheckString(1))
	key := L.CheckString(2)
	data := L.CheckString(3)
	var hf func() hash.Hash
	switch algo {
	case "md5":
		hf = md5.New
	case "sha1":
		hf = sha1.New
	case "sha256":
		hf = sha256.New
	default:
		hf = sha1.New
	}
	mac := hmac.New(hf, []byte(key))
	mac.Write([]byte(data))
	L.Push(lua.LString(string(mac.Sum(nil))))
	return 1
}

func opensslRandBytes(L *lua.LState) int {
	n := L.CheckInt(1)
	if n < 0 {
		n = 0
	}
	if n > 1<<20 {
		n = 1 << 20
	}
	b := make([]byte, n)
	_, _ = rand.Read(b)
	L.Push(lua.LString(string(b)))
	return 1
}

// Nmap uses encrypt/decrypt(cipher, key, iv, data[, padding]). SMB's DES
// calls pass a nil IV; it is not the key or the input data.
func opensslEncrypt(L *lua.LState) int {
	algo := stringsToLower(L.CheckString(1))
	key := []byte(L.CheckString(2))
	data := []byte(L.CheckString(4))
	switch {
	case stringsHasPrefix(algo, "des"):
		for len(key) < 8 {
			key = append(key, 0)
		}
		block, err := des.NewCipher(key[:8])
		if err != nil {
			L.Push(lua.LNil)
			return 1
		}
		if len(data) < 8 {
			pad := make([]byte, 8)
			copy(pad, data)
			data = pad
		}
		out := make([]byte, 8)
		block.Encrypt(out, data[:8])
		L.Push(lua.LString(string(out)))
		return 1
	default:
		L.Push(lua.LNil)
		return 1
	}
}

func opensslDecrypt(L *lua.LState) int {
	algo := stringsToLower(L.CheckString(1))
	key := []byte(L.CheckString(2))
	data := []byte(L.CheckString(4))
	switch {
	case stringsHasPrefix(algo, "des"):
		for len(key) < 8 {
			key = append(key, 0)
		}
		block, err := des.NewCipher(key[:8])
		if err != nil || len(data) < 8 {
			L.Push(lua.LNil)
			return 1
		}
		out := make([]byte, 8)
		block.Decrypt(out, data[:8])
		L.Push(lua.LString(string(out)))
		return 1
	default:
		L.Push(lua.LNil)
		return 1
	}
}

// DES_string_to_key implements the classic DES str-to-key used by NTLM/SMB.
func opensslDESStringToKey(L *lua.LState) int {
	s := []byte(L.CheckString(1))
	key := make([]byte, 8)
	for i := 0; i < 7 && i < len(s); i++ {
		key[i] = s[i]
	}
	// expand 7 bytes to 8 with parity bits (simplified)
	out := make([]byte, 8)
	out[0] = key[0] >> 1
	out[1] = ((key[0]&0x01)<<6 | key[1]>>2)
	out[2] = ((key[1]&0x03)<<5 | key[2]>>3)
	out[3] = ((key[2]&0x07)<<4 | key[3]>>4)
	out[4] = ((key[3]&0x0f)<<3 | key[4]>>5)
	out[5] = ((key[4]&0x1f)<<2 | key[5]>>6)
	out[6] = ((key[5]&0x3f)<<1 | key[6]>>7)
	out[7] = key[6] & 0x7f
	for i := range out {
		out[i] = (out[i] << 1)
	}
	L.Push(lua.LString(string(out)))
	return 1
}

func bnFromUD(L *lua.LState, n int) *big.Int {
	ud := L.CheckUserData(n)
	if v, ok := ud.Value.(*big.Int); ok {
		return v
	}
	L.ArgError(n, "bignum expected")
	return nil
}

func pushBN(L *lua.LState, v *big.Int) int {
	ud := L.NewUserData()
	ud.Value = v
	L.Push(ud)
	return 1
}

func opensslBignumBin2BN(L *lua.LState) int {
	b := []byte(L.CheckString(1))
	return pushBN(L, new(big.Int).SetBytes(b))
}
func opensslBignumBN2Bin(L *lua.LState) int {
	v := bnFromUD(L, 1)
	L.Push(lua.LString(string(v.Bytes())))
	return 1
}
func opensslBignumBN2Dec(L *lua.LState) int {
	v := bnFromUD(L, 1)
	L.Push(lua.LString(v.String()))
	return 1
}
func opensslBignumDec2BN(L *lua.LState) int {
	s := L.CheckString(1)
	v := new(big.Int)
	if _, ok := v.SetString(s, 10); !ok {
		L.Push(lua.LNil)
		return 1
	}
	return pushBN(L, v)
}
func opensslBignumHex2BN(L *lua.LState) int {
	s := L.CheckString(1)
	v := new(big.Int)
	if _, ok := v.SetString(s, 16); !ok {
		L.Push(lua.LNil)
		return 1
	}
	return pushBN(L, v)
}
func opensslBignumModExp(L *lua.LState) int {
	base := bnFromUD(L, 1)
	exp := bnFromUD(L, 2)
	mod := bnFromUD(L, 3)
	return pushBN(L, new(big.Int).Exp(base, exp, mod))
}
func opensslBignumPseudoRand(L *lua.LState) int {
	bits := L.CheckInt(1)
	if bits < 1 {
		bits = 1
	}
	max := new(big.Int).Lsh(big.NewInt(1), uint(bits))
	v, err := rand.Int(rand.Reader, max)
	if err != nil {
		L.Push(lua.LNil)
		return 1
	}
	return pushBN(L, v)
}

func stringsToLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

func stringsHasPrefix(s, p string) bool {
	return len(s) >= len(p) && s[:len(p)] == p
}
