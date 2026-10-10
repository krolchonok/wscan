package nse

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"time"

	lua "github.com/yuin/gopher-lua"
)

// registerNmapSocket adds the nmap.socket sub-table real nmap exposes
// alongside nmap.new_socket(...). Only parse_ssl_certificate is implemented
// — library/nmap/nselib/sslcert.lua (and transitively any script that
// requires "sslcert", e.g. the *-ntlm-info.nse family) assigns it at
// module-load time: "_ENV.parse_ssl_certificate = nmap.socket.parse_ssl_certificate".
// Without this field existing, that assignment itself fails ("attempt to
// index a non-table object(nil)") and the whole module — and every script
// requiring it — never loads, even for scripts whose own logic never
// touches TLS. A missing nmap.socket table turns one unrelated unimplemented
// function into every consumer of sslcert.lua silently producing zero
// findings.
func registerNmapSocket(L *lua.LState, mod *lua.LTable) {
	socket := L.NewTable()
	L.SetFuncs(socket, map[string]lua.LGFunction{
		"parse_ssl_certificate": nmapSocketParseSSLCertificate,
	})
	L.SetField(mod, "socket", socket)
}

// nmapSocketParseSSLCertificate mirrors nmap's nmap.socket.parse_ssl_certificate(der):
// parse a DER-encoded X.509 certificate and return the fields sslcert.lua's
// consumers (ssl-cert.nse and friends) read. Field names match nmap's
// OpenSSL-derived naming (commonName, organizationName, ...) and the
// validity dates use the same shape as os.date("*t") since that is what
// real nmap returns. Extension parsing is not implemented — returned as an
// empty table so ipairs()/# over it is safe, just never finds anything.
func nmapSocketParseSSLCertificate(L *lua.LState) int {
	der := L.CheckString(1)
	cert, err := x509.ParseCertificate([]byte(der))
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}
	t := L.NewTable()
	L.SetField(t, "subject", x509NameTable(L, cert.Subject))
	L.SetField(t, "issuer", x509NameTable(L, cert.Issuer))
	L.SetField(t, "pem", lua.LString(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))))
	L.SetField(t, "sig_algorithm", lua.LString(cert.SignatureAlgorithm.String()))
	L.SetField(t, "serial", lua.LString(cert.SerialNumber.String()))

	validity := L.NewTable()
	L.SetField(validity, "notBefore", timeFieldsTable(L, cert.NotBefore.UTC()))
	L.SetField(validity, "notAfter", timeFieldsTable(L, cert.NotAfter.UTC()))
	L.SetField(t, "validity", validity)

	pubkey := L.NewTable()
	bits, typ := pubkeyInfo(cert)
	L.SetField(pubkey, "bits", lua.LNumber(bits))
	L.SetField(pubkey, "type", lua.LString(typ))
	L.SetField(t, "pubkey", pubkey)

	L.SetField(t, "extensions", L.NewTable())
	L.Push(t)
	return 1
}

func x509NameTable(L *lua.LState, name pkix.Name) *lua.LTable {
	t := L.NewTable()
	set := func(key, val string) {
		if val != "" {
			L.SetField(t, key, lua.LString(val))
		}
	}
	set("commonName", name.CommonName)
	set("serialNumber", name.SerialNumber)
	if len(name.Organization) > 0 {
		set("organizationName", name.Organization[0])
	}
	if len(name.OrganizationalUnit) > 0 {
		set("organizationalUnitName", name.OrganizationalUnit[0])
	}
	if len(name.Country) > 0 {
		set("countryName", name.Country[0])
	}
	if len(name.Province) > 0 {
		set("stateOrProvinceName", name.Province[0])
	}
	if len(name.Locality) > 0 {
		set("localityName", name.Locality[0])
	}
	return t
}

// timeFieldsTable matches the shape os.date("*t") produces, since that is
// what real nmap's validity.notBefore/notAfter tables use.
func timeFieldsTable(L *lua.LState, tm time.Time) *lua.LTable {
	t := L.NewTable()
	L.SetField(t, "year", lua.LNumber(tm.Year()))
	L.SetField(t, "month", lua.LNumber(int(tm.Month())))
	L.SetField(t, "day", lua.LNumber(tm.Day()))
	L.SetField(t, "hour", lua.LNumber(tm.Hour()))
	L.SetField(t, "min", lua.LNumber(tm.Minute()))
	L.SetField(t, "sec", lua.LNumber(tm.Second()))
	return t
}

func pubkeyInfo(cert *x509.Certificate) (bits int, typ string) {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return pub.N.BitLen(), "rsa"
	case *ecdsa.PublicKey:
		return pub.Curve.Params().BitSize, "ec"
	case ed25519.PublicKey:
		return len(pub) * 8, "ed25519"
	default:
		return 0, "unknown"
	}
}
