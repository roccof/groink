-- Copyright (c) Denatured Ethyl Crew
--
-- This file is part of GroinK.
--
-- GroinK is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
--
-- GroinK is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with GroinK.  If not, see <http://www.gnu.org/licenses/>.

-- dissector.lua
-- dissect payload and return username and passwd

local base64 = require("base64")
local httplib = require("http")
local urllib = require("urllib")
local pairs = pairs
local string = require("string")
local util = require("util")

module("dissector")

local usr_regex = {"u", ".*account.*", ".*acct.*", ".*domain.*", ".*login.*", 
		   ".*member.*", ".*user.*", ".*name", ".*email", ".*_id", "id", 
		   "uid", "mn", "mailaddress", ".*usr.*", ".*admin.*"}

local pwd_regex = {".*password.*", ".*passwd.*", ".*pass.*", ".*pw", "pw.*", "additional_info", ".*pw.*"}

local function get_uri_params(p)
   local params = {}

   local t = util.strsplit(p, "&")

   for _,v in pairs(t) do
      if v ~= nil then
	 local param = util.strsplit(v, "=")
	 params[param[1]] = param[2]
      end
   end

   return params
end

local function list_match(str, regex_list)
   for _,v in pairs(regex_list) do
      if str:match(v) ~= nil then
	 return true
      end
   end
   return false
end

local function check_login(params)
   local user, passwd = nil, nil

   -- check for username
   for k,v in pairs(params) do
      if list_match(k:lower(), usr_regex) then
	 user = v
	 break
      end
   end

   -- check for password
   for k,v in pairs(params) do
      if list_match(k:lower(), pwd_regex) then
	 passwd = v
	 break
      end
   end

   if user == nil and passwd == nil then
      return nil, nil
   end

   return user, passwd
end

-- HTTP dissector
function dissect_http(data)

   local info, usr, pwd = nil, nil, nil

   local http = httplib.parse_http(data)

   if http == nil then
      return nil
   end

   if http.type ~= httplib.HTTP_TYPE_REQUEST then
      return nil
   end

   if not http.method == "GET" or not http.method == "POST" then
      return nil
   end

   if http.headers["Authorization"] ~= nil then
      local val = http.headers["Authorization"]
      local s, e = val:find("Basic")
      if s ~= nil  then
	 local cred =  base64.decode(val:sub(e + 2, val:len()))
	 local cs, ce = cred:find(":")
	 usr = cred:sub(1, cs-1)
	 pwd = cred:sub(ce+1, cred:len())
	 info = "HTTP WWW-Authorization Basic " .. http.headers["Host"] .. http.uri
      end
   elseif http.headers["Proxy-Authorization"] ~= nil then
      local val = http.headers["Proxy-Authorization"]
      local s, e = val:find("Basic")
      if s ~= nil  then
	 local cred =  base64.decode(val:sub(e + 2, val:len()))
	 local cs, ce = cred:find(":")
	 usr = cred:sub(1, cs-1)
	 pwd = cred:sub(ce+1, cred:len())
	 info = "HTTP Proxy-Authorization Basic " .. http.headers["Host"] .. http.uri
      end
   elseif http.method == "GET" then
      local uri = http.uri
      local s, e = uri:find("?")
      if s ~= nil then
	 local str_params = uri:sub(s+1, uri:len())
	 local params = get_uri_params(urllib.url_decode(str_params))

	 usr, pwd = check_login(params)
	 info = "HTTP GET " .. http.headers["Host"]

	 if usr == nil or pwd == nil then
	    return
	 end
      end
   elseif http.method == "POST" then
      local ctype = http.headers["Content-Type"]

      if ctype ~= nil and ctype == "application/x-www-form-urlencoded" and http.body ~= nil then
	 local params = get_uri_params(urllib.url_decode(http.body))

	 usr, pwd = check_login(params)
	 info = "HTTP POST " .. http.headers["Host"]

	 if usr == nil or pwd == nil then
	    return
	 end
      end
   end
   
   return info, usr, pwd
end

function dissect_ftp(data)
   
end