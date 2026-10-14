package nse

import lua "github.com/yuin/gopher-lua"

// stdnseMakeBuffer returns a line/pattern reader, including bytes already
// consumed while connecting. FTP uses it for banners and multiline replies.
func stdnseMakeBuffer(L *lua.LState) int {
	s := checkSocket(L)
	socket := L.Get(1)
	separator := L.CheckString(2)
	initial := L.OptString(3, "")
	s.buf = append([]byte(initial), s.buf...)
	var finished lua.LValue
	L.Push(L.NewFunction(func(L *lua.LState) int {
		if finished != nil {
			L.Push(lua.LNil)
			L.Push(finished)
			return 2
		}
		top := L.GetTop()
		reader, ok := L.GetField(socket, "receive_buf").(*lua.LFunction)
		if !ok {
			L.RaiseError("stdnse.make_buffer: socket has no receive_buf method")
			return 0
		}
		if err := L.CallByParam(lua.P{Fn: reader, NRet: 2, Protect: true}, socket, lua.LString(separator), lua.LFalse); err != nil {
			L.SetTop(top)
			L.RaiseError("%v", err)
			return 0
		}
		status, data := L.Get(-2), L.Get(-1)
		L.SetTop(top)
		if lua.LVAsBool(status) {
			L.Push(data)
			return 1
		}
		finished = data
		if len(s.buf) > 0 {
			tail := string(s.buf)
			s.buf = nil
			L.Push(lua.LString(tail))
			return 1
		}
		L.Push(lua.LNil)
		L.Push(data)
		return 2
	}))
	return 1
}
