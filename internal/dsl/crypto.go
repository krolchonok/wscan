package dsl

import (
	crand "crypto/rand"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/hdm/jarm-go"
)

func init() {
	functions["hmac"] = func(a []any) (any, error) {
		if err := need(a, 3, "hmac"); err != nil {
			return nil, err
		}
		h := newHMAC(toString(a[0]), []byte(toString(a[2])))
		if h == nil {
			return "", fmt.Errorf("hmac: unsupported algorithm %q", toString(a[0]))
		}
		_, _ = h.Write([]byte(toString(a[1])))
		return hex.EncodeToString(h.Sum(nil)), nil
	}
	functions["aes_cbc"] = func(a []any) (any, error) {
		if err := need(a, 3, "aes_cbc"); err != nil {
			return nil, err
		}
		data, key, iv := []byte(toString(a[0])), []byte(toString(a[1])), []byte(toString(a[2]))
		block, err := aes.NewCipher(normalizeAESKey(key))
		if err != nil {
			return "", err
		}
		if len(iv) < aes.BlockSize {
			return "", fmt.Errorf("aes_cbc: iv too short")
		}
		iv = iv[:aes.BlockSize]
		padded := pkcs7Pad(data, aes.BlockSize)
		out := make([]byte, len(padded))
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)
		return string(out), nil
	}
	functions["aes_gcm"] = func(a []any) (any, error) {
		if err := need(a, 2, "aes_gcm"); err != nil {
			return nil, err
		}
		data, key := []byte(toString(a[0])), []byte(toString(a[1]))
		nonce := make([]byte, 12)
		if len(a) > 2 {
			copy(nonce, []byte(toString(a[2])))
		} else {
			_, _ = crand.Read(nonce)
		}
		block, err := aes.NewCipher(normalizeAESKey(key))
		if err != nil {
			return "", err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return "", err
		}
		return string(gcm.Seal(nonce, nonce, data, nil)), nil
	}
	functions["rand_ip"] = func(a []any) (any, error) {
		return fmt.Sprintf("%d.%d.%d.%d", rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256)), nil
	}
	functions["generate_java_gadget"] = func(a []any) (any, error) {
		if err := need(a, 2, "generate_java_gadget"); err != nil {
			return nil, err
		}
		kind := strings.ToLower(toString(a[0]))
		dest := toString(a[1])
		encoding := "raw"
		if len(a) > 2 {
			encoding = strings.ToLower(toString(a[2]))
		}
		var payload []byte
		switch kind {
		case "dns", "urldns":
			payload = javaURLDNS(dest)
		case "commons-collections3.1", "commons-collections", "commonscollections1":
			// Full CC gadgets are out of scope here; URLDNS still produces a
			// valid serialized blob and may trigger OAST on permissive targets.
			payload = javaURLDNS(dest)
		default:
			return "", fmt.Errorf("generate_java_gadget: unsupported type %q", kind)
		}
		switch encoding {
		case "base64":
			return functions["base64"]([]any{string(payload)})
		case "hex":
			return hex.EncodeToString(payload), nil
		default:
			return string(payload), nil
		}
	}
	functions["jarm"] = func(a []any) (any, error) {
		if err := need(a, 1, "jarm"); err != nil {
			return nil, err
		}
		host := toString(a[0])
		port := 443
		if h, p, err := net.SplitHostPort(host); err == nil {
			host = h
			if pn, err := strconv.Atoi(p); err == nil {
				port = pn
			}
		}
		if len(a) > 1 {
			port = int(toNumber(a[1]))
		}
		return jarmFingerprint(host, port), nil
	}
}

func newHMAC(algo string, key []byte) hash.Hash {
	switch strings.ToLower(algo) {
	case "md5":
		return hmac.New(md5.New, key)
	case "sha1":
		return hmac.New(sha1.New, key)
	case "sha256":
		return hmac.New(sha256.New, key)
	case "sha512":
		return hmac.New(sha512.New, key)
	}
	return nil
}

func normalizeAESKey(key []byte) []byte {
	switch len(key) {
	case 16, 24, 32:
		return key
	}
	sum := sha256.Sum256(key)
	return sum[:]
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	pad := blockSize - len(data)%blockSize
	out := make([]byte, len(data)+pad)
	copy(out, data)
	for i := len(data); i < len(out); i++ {
		out[i] = byte(pad)
	}
	return out
}

func jarmFingerprint(host string, port int) string {
	results := make([]string, 0, 10)
	for _, probe := range jarm.GetProbes(host, port) {
		addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
		c, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if err != nil {
			return ""
		}
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err = c.Write(jarm.BuildProbe(probe)); err != nil {
			results = append(results, "")
			_ = c.Close()
			continue
		}
		buff := make([]byte, 1484)
		_, _ = c.Read(buff)
		_ = c.Close()
		ans, err := jarm.ParseServerHello(buff, probe)
		if err != nil {
			results = append(results, "")
			continue
		}
		results = append(results, ans)
	}
	return jarm.RawHashToFuzzyHash(strings.Join(results, ","))
}
