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
local table = require("table")

local print = print

module("dissector")

-- Dissector sessions
local d_sess = {}

local usr_regex = {"u", ".*account.*", ".*acct.*", ".*domain.*", ".*login.*", 
		   ".*member.*", ".*user.*", ".*name", ".*email", ".*_id", "id", 
		   "uid", "mn", "mailaddress", ".*usr.*", ".*admin.*"}

local pwd_regex = {".*password.*", ".*passwd.*", ".*pass.*", ".*pw", "pw.*", ".*pw.*", "additional_info"}

local function new_session(src_addr, dst_addr, src_port, dst_port, proto, data)

   -- return the session obj
   return {src = src_addr, dst = dst_addr, src_p = src_port, 
	   dst_p = dst_port, proto = proto, data = data }
end

-- Insert a new session in the list
local function set_session(s)
   table.insert(d_sess, s)
end

-- Remove and return a session from the list
local function get_session(src_addr, dst_addr, src_port, dst_port, proto)
   for k,v in pairs(d_sess) do
      if v.proto == proto and v.src == src_addr and v.dst == dst_addr and v.src_p == src_port and v.dst_p == dst_port then
	 local s = v
	 table.remove(d_sess, k)
	 return s
      end
   end
   return nil
end

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
function dissect_http(packet)

   local info, usr, pwd = nil, nil, nil

   local p = packet:payload()
   
   if p == nil then
      return nil
   end

   local http = httplib.parse_http(p:dissect().data)

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

-- FTP dissector
function dissect_ftp(packet)
   local info = "FTP"

   local p = packet:payload()
   
   if p == nil then
      return nil
   end

   local data = p:dissect().data

   local s,e = data:find("USER")

   if s ~= nil then
      -- save session info

      local usr = data:sub(e+2, #data-1)

      local s = new_session(packet:net_srcaddr(), packet:net_dstaddr(), 
			    packet:src_port(), packet:dst_port(), 
			    p.proto, usr)

      set_session(s)
      return nil
   end

   s,e = data:find("PASS")

   if s ~= nil then

      local pwd = data:sub(e+2, #data-1)

      -- retrieve stored session info
      local s = get_session(packet:net_srcaddr(), packet:net_dstaddr(), 
			    packet:src_port(), packet:dst_port(), 
			    p.proto)
      if s ~= nil then
	 return info, s.data, pwd
      end
   end

   return nil
end