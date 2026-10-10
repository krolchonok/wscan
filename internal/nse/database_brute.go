package nse

import lua "github.com/yuin/gopher-lua"

func databaseSequentialBrute(id string) bool {
	switch id {
	case "mysql-brute", "redis-brute", "mongodb-brute", "cassandra-brute", "informix-brute", "oracle-brute":
		return true
	}
	return false
}
func installDatabaseBrute(L *lua.LState) error {
	return L.DoString(`
local brute = require "brute"
local creds = require "creds"
local unpwdb = require "unpwdb"
local stdnse = require "stdnse"
local nmap = require "nmap"
brute.new_socket = function() return nmap.new_socket() end
brute.Engine.start = function(self)
 local worker = coroutine.wrap(function()
  local limit = tonumber(stdnse.get_script_args("brute.guesses")) or 3
  if limit < 1 or limit > 100 or limit ~= math.floor(limit) then error("brute.guesses must be 1..100") end
  local delay = tonumber(stdnse.get_script_args("brute.delay")) or 0
  if delay < 0 or delay > 3600 or delay ~= delay then error("invalid brute.delay") end
  if stdnse.get_script_args("brute.credfile") and not self.iterator then error("brute.credfile requires an explicit credential iterator") end
  local iterator = self.iterator
  if type(self.usernames) ~= "function" or type(self.passwords) ~= "function" then error("database dictionary unavailable") end
  if not iterator then
   if self.options.passonly then
    local sent=false
    local function single(command) if command=="reset" then sent=false;return end;if sent then return nil end;sent=true;return "" end
    iterator = brute.Iterators.user_pw_iterator(single, self.passwords)
   else
    local mode=self.options.mode or stdnse.get_script_args("brute.mode")
    if mode and mode~="user" and mode~="pass" then error("unsupported database brute.mode") end
    if mode=="user" then iterator=brute.Iterators.user_pw_iterator(self.usernames,self.passwords) else iterator = brute.Iterators.pw_user_iterator(self.usernames, self.passwords) end
    if self.options.useraspass then iterator = unpwdb.concat_iterators(brute.Iterators.pw_same_as_user_iterator(self.usernames,"lower"),iterator) end
   end
  end
  if self.options.emptypass and not self.options.passonly then
   local sent=false
   local function empty(command) if command=="reset" then sent=false;return end;if sent then return nil end;sent=true;return "" end
   iterator=unpwdb.concat_iterators(brute.Iterators.pw_user_iterator(self.usernames,empty),iterator)
  end
  local found, counts, seen, accounts = {}, {}, {}, {}
  local guesses = 0
  local examined = 0
  if self.driver:new(self.host,self.port,self.driver_options).check then
   local ok,response = self.driver:new(self.host,self.port,self.driver_options):check()
   if not ok then error("database driver check failed: "..tostring(response)) end
  end
  while true do
   examined=examined+1
   if examined>1000000 then error("database credential iterator exceeded limit") end
   local user,pass = iterator()
   if user == nil and pass == nil then break end
   user,pass = user or "",pass or ""
   local key = user.."\0"..pass
   if not found[user] and not seen[key] and (counts[user] or 0)<limit then
    seen[key]=true
    if guesses>0 and delay>0 then stdnse.sleep(delay) end
    local driver=self.driver:new(self.host,self.port,self.driver_options)
    local connected,response=driver:connect()
    if not connected then pcall(function() driver:disconnect() end);error("database transport error: "..tostring(type(response)=="table" and response.msg or response)) end
    counts[user]=(counts[user] or 0)+1;guesses=guesses+1
    local called,ok,account=pcall(function() return driver:login(user,pass) end)
    driver:disconnect()
    if not called then error(ok) end
    if ok then
     if not account or account.state ~= creds.StateMsg[creds.State.VALID] or (account.username ~= user and not self.options.passonly) then error("database account state does not confirm successful login") end
     found[user]=true
     accounts[#accounts+1]=(user=="" and "(password-only)" or user)..": valid credential (password omitted)"
     if self.options.firstonly then break end
    elseif account and type(account)=="table" then
     if account:isAbort() or account:isRetry() or account:isReduce() then error("database login indeterminate: "..tostring(account.msg)) end
     if account:isDone() or account:isInvalidAccount() then found[user]=true end
    else error("database login returned no rejection evidence") end
   end
  end
  local result=stdnse.output_table()
  if #accounts>0 then result.Accounts=accounts end
  result.Statistics=string.format("Performed %d guesses; limit %d per username; sequential",guesses,limit)
  return true,result
 end)
 return worker()
end
`)
}
