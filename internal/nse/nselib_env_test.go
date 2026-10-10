package nse

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	lua "github.com/yuin/gopher-lua"
)

// Regression coverage for two gopher-lua (Lua 5.1) vs. real nmap (Lua 5.2+)
// gaps in loadTransformedNselib's env prologue — see its comment for the
// full explanation. Both were first observed as real scan errors:
// "nmap/scripts/{imap,pop3,smtp}-ntlm-info.nse: ... attempt to index a
// non-table object(boolean/nil) with key 'enc'/'parse_ssl_certificate'".

// TestNselibBitopUnderModuleIsolation covers gap 2: a nselib module that
// isolates its globals via "_ENV = require 'stdnse'.module(name)" must
// still be able to call the Go-provided bit.* functions our bitop rewrite
// (a>>2 -> bit.rshift(a,2), ...) injects, even though the original source
// never referenced "bit" itself and the isolated env has no fallback to it.
func TestNselibBitopUnderModuleIsolation(t *testing.T) {
	lib := libraryDir(t)
	r := New(lib, Config{})
	L := lua.NewState()
	defer L.Close()
	ctrl := newControl(context.Background(), Config{Timeout: 5 * time.Second})
	defer ctrl.close()
	r.registerModules(L, ctrl, "nselib-bitop-test")
	err := L.DoString(`
local base64 = require("base64")
if type(base64) ~= "table" then error("require('base64') returned " .. type(base64) .. ", want table") end
local got = base64.enc("hello")
if got ~= "aGVsbG8=" then error("base64.enc('hello') = " .. tostring(got) .. ", want aGVsbG8=") end
`)
	if err != nil {
		t.Fatalf("base64.enc under module isolation: %v", err)
	}
}

// TestNtlmInfoScriptsLoad covers both gaps end to end: these three real
// scripts all require "smbauth" (which requires "base64", exercising the
// bitop fix), and imap-ntlm-info.nse also requires "sslcert", whose
// "_ENV.parse_ssl_certificate = nmap.socket.parse_ssl_certificate" line
// needs nmap.socket to exist (gap this covers separately, see sslcert.go).
func TestNtlmInfoScriptsLoad(t *testing.T) {
	lib := libraryDir(t)
	for _, name := range []string{"imap-ntlm-info.nse", "pop3-ntlm-info.nse", "smtp-ntlm-info.nse"} {
		name := name
		t.Run(name, func(t *testing.T) {
			src, err := os.ReadFile(filepath.Join(lib, "nmap/scripts", name))
			if err != nil {
				t.Fatal(err)
			}
			id := strings.TrimSuffix(name, ".nse")
			L := lua.NewState()
			defer L.Close()
			r := New(lib, Config{})
			ctrl := newControl(context.Background(), Config{Timeout: 5 * time.Second})
			defer ctrl.close()
			r.registerModules(L, ctrl, id)
			L.SetGlobal("SCRIPT_NAME", lua.LString(id))
			L.SetGlobal("SCRIPT_TYPE", lua.LString("portrule"))
			if err := L.DoString(transformLua53(string(src))); err != nil {
				t.Fatalf("load: %v", err)
			}
		})
	}
}

// TestNmapSocketParseSSLCertificate covers gap 1 directly: a real DER
// certificate round-trips through nmap.socket.parse_ssl_certificate with
// the fields sslcert.lua's consumers read.
func TestNmapSocketParseSSLCertificate(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "nselib-test.example", Organization: []string{"wscan"}},
		NotBefore:    time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC),
		NotAfter:     time.Date(2025, 6, 7, 8, 9, 10, 0, time.UTC),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	lib := libraryDir(t)
	r := New(lib, Config{})
	L := lua.NewState()
	defer L.Close()
	ctrl := newControl(context.Background(), Config{Timeout: 5 * time.Second})
	defer ctrl.close()
	r.registerModules(L, ctrl, "sslcert-test")
	L.SetGlobal("DER", lua.LString(string(der)))
	err = L.DoString(`
local nmap = require("nmap")
local cert, err = nmap.socket.parse_ssl_certificate(DER)
if not cert then error("parse_ssl_certificate failed: " .. tostring(err)) end
if cert.subject.commonName ~= "nselib-test.example" then
  error("subject.commonName = " .. tostring(cert.subject.commonName))
end
if cert.validity.notBefore.year ~= 2024 then
  error("validity.notBefore.year = " .. tostring(cert.validity.notBefore.year))
end
if cert.pubkey.type ~= "rsa" or cert.pubkey.bits ~= 2048 then
  error("pubkey = " .. tostring(cert.pubkey.type) .. "/" .. tostring(cert.pubkey.bits))
end
if not cert.pem:find("BEGIN CERTIFICATE") then
  error("pem missing BEGIN CERTIFICATE header")
end
`)
	if err != nil {
		t.Fatal(err)
	}
}
