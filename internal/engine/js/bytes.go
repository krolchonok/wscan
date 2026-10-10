package js

import (
	"encoding/hex"

	"github.com/dop251/goja"
)

// bytesModule exposes bytes.Buffer two ways real templates use it:
// `bytes.NewBuffer()` (plain call) and `new bytes.Buffer()` (constructor —
// e.g. CVE-2024-51978.yaml's `const buffer = new bytes.Buffer();"). A plain
// FunctionCall-shaped factory only supports the first; see smbModule's doc
// comment for why `new` then fails with "Value is not a constructor".
func bytesModule(vm *goja.Runtime) goja.Value {
	obj := vm.NewObject()
	ctor := func(call goja.ConstructorCall) *goja.Object {
		if len(call.Arguments) > 0 {
			if b, ok := call.Argument(0).Export().([]byte); ok {
				return vm.ToValue(&Buffer{buf: append([]byte(nil), b...)}).(*goja.Object)
			}
		}
		return vm.ToValue(&Buffer{}).(*goja.Object)
	}
	_ = obj.Set("NewBuffer", ctor)
	_ = obj.Set("Buffer", ctor)
	return obj
}

// Buffer mirrors nuclei/bytes.Buffer used by templates via bytes.NewBuffer().
type Buffer struct {
	buf []byte
}

func (b *Buffer) Write(data []byte) *Buffer {
	b.buf = append(b.buf, data...)
	return b
}

func (b *Buffer) WriteString(data string) *Buffer {
	b.buf = append(b.buf, []byte(data)...)
	return b
}

func (b *Buffer) Bytes() []byte  { return b.buf }
func (b *Buffer) String() string { return string(b.buf) }
func (b *Buffer) Len() int       { return len(b.buf) }
func (b *Buffer) Hex() string    { return hex.EncodeToString(b.buf) }
func (b *Buffer) Hexdump() string {
	return hex.Dump(b.buf)
}
