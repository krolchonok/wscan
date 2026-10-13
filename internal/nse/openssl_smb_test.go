package nse

import (
	"context"
	"testing"
	"time"

	lua "github.com/yuin/gopher-lua"
)

func TestSMBAuthenticationUsesNmapOpenSSLArgumentOrder(t *testing.T) {
	L := lua.NewState()
	defer L.Close()
	r := New(libraryDir(t), Config{})
	ctrl := newControl(context.Background(), Config{Timeout: time.Second})
	defer ctrl.close()
	r.registerModules(L, ctrl, "smb-auth-regression")
	if err := L.DoString(`
local smbauth = require "smbauth"
local openssl = require "openssl"
local function hex(s)
  return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end
for password, expected in pairs({
  [""] = "aad3b435b51404eeaad3b435b51404ee",
  ["PASSWORD"] = "e52cac67419a9a224a3b108f3fa6cb6d",
}) do
  local padded = password .. string.rep("\0", 14 - #password)
  local hash = openssl.encrypt("DES", openssl.DES_string_to_key(padded:sub(1, 7)), nil, "KGS!@#$%")
    .. openssl.encrypt("DES", openssl.DES_string_to_key(padded:sub(8, 14)), nil, "KGS!@#$%")
  assert(hex(hash) == expected, "incorrect LM hash for " .. password)
end
local lm, ntlm = smbauth.get_password_response("guest", "", "", nil, "v1", "12345678", false)
assert(type(lm) == "string" and #lm == 24 and type(ntlm) == "string" and #ntlm == 24)
local key = openssl.DES_string_to_key("PASSWOR")
local encrypted = openssl.encrypt("DES", key, nil, "KGS!@#$%")
assert(openssl.decrypt("DES", key, nil, encrypted) == "KGS!@#$%")
`); err != nil {
		t.Fatal(err)
	}
}
