package nse

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSequentialDatabaseBruteAdapter(t *testing.T) {
	lib, err := filepath.Abs("../../library")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	users, passes := filepath.Join(dir, "users"), filepath.Join(dir, "passes")
	os.WriteFile(users, []byte("alice\n"), 0600)
	os.WriteFile(passes, []byte("wrong\nother\n"), 0600)
	script := filepath.Join(dir, "mongodb-brute.nse")
	source := `local brute=require "brute"
local creds=require "creds"
portrule=function() return true end
Driver={new=function(self,h,p) return setmetatable({}, {__index=self}) end,
connect=function() return true end,disconnect=function() return true end,
login=function(self,u,p) if p=="alice" then return true,creds.Account:new(u,p,creds.State.VALID) end;return false,brute.Error:new("Incorrect password") end}
action=function(host,port) local e=brute.Engine:new(Driver,host,port);e.options.script_name=SCRIPT_NAME;local ok,out=e:start();return out end`
	if err := os.WriteFile(script, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	r := New(lib, Config{Args: map[string]string{"userdb": users, "passdb": passes, "brute.guesses": "1"}})
	result, ran, err := r.Run(context.Background(), script, HostInfo{IP: "127.0.0.1"}, []PortInfo{{Number: 27017, Protocol: "tcp"}})
	if err != nil || !ran || len(result) != 1 || !strings.Contains(result[0].Output, "alice: valid credential") || !strings.Contains(result[0].Output, "Performed 1 guesses") {
		t.Fatalf("result=%v ran=%v err=%v", result, ran, err)
	}
	rejected := strings.Replace(source, `if p=="alice" then`, `if false then`, 1)
	os.WriteFile(script, []byte(rejected), 0600)
	result, _, err = r.Run(context.Background(), script, HostInfo{IP: "127.0.0.1"}, []PortInfo{{Number: 27017, Protocol: "tcp"}})
	if err != nil || len(result) != 1 || strings.Contains(result[0].Output, "valid credential") || !strings.Contains(result[0].Output, "Performed 1 guesses") {
		t.Fatalf("rejection/limit: %v %v", result, err)
	}
	source = strings.Replace(source, `connect=function() return true end`, `connect=function() return false,"TIMEOUT" end`, 1)
	os.WriteFile(script, []byte(source), 0600)
	_, _, err = r.Run(context.Background(), script, HostInfo{IP: "127.0.0.1"}, []PortInfo{{Number: 27017, Protocol: "tcp"}})
	if err == nil || !strings.Contains(err.Error(), "database transport error") {
		t.Fatalf("transport error hidden: %v", err)
	}
}
