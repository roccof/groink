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

-- http.lua
-- rfc 2616

local string = require("string")

local print = print

module(... or "http", package.seeall)

HTTP_TYPE_REQUEST = 0
HTTP_TYPE_RESPONSE = 1

local response_phrase = {
   -- TODO
}

local http_methods = { "GET", "HEAD", "POST", "CONNECT", "TRACE", "OPTIONS", "PUT", "DELETE" }

local function validate_request_method(method)
   for _,v in pairs(http_methods) do
      if method == v then
	 return true
      end
   end
   return false
end

local function next_line(buf, pos)
   local line, s, e

   s, e = string.find(buf, "\r\n", pos)
   
   if s == nil then
      return nil, pos
   end
   
   line = string.sub(buf, pos, s - 1)
   pos = e + 1; -- Skip CRLF

   return line, pos
end

local function parse_status_line(line)
   local sl = {}

   if string.match(line, "^(HTTP/%d.%d%s%d+%s.*)$") ~= nil then
      -- response message
      local version, status, reason_phrase = 
   	 string.match(line, "^HTTP/(%d%.%d) *(%d+) *(.*)$")
      
      sl["type"] = HTTP_TYPE_RESPONSE
      sl["version"] = version
      sl["status"] = status
      sl["reason_phrase"] = reason_phrase
      
      return sl
   elseif string.match(line, "^(%u+%s.+%sHTTP/%d.%d)$") ~= nil then
      -- request message
      local method, uri, version = 
   	 string.match(line, "^(%u+)%s*(.+)%sHTTP/(%d.%d)$")
      
      if not validate_request_method(method) then
   	 return nil, "invalid request method"
      end

      sl["type"] = HTTP_TYPE_REQUEST
      sl["method"] = method
      sl["uri"] = uri
      sl["version"] = version
      
      return sl
   else
      return nil, "invalid status-line"
   end
end

-- Http class
Http = {}

function parse_http(data)
   local http, line, off = {}, nil, 1

   -- first get the status-line
   line, off = next_line(data, off)

   if line == nil then
      -- no status line???
      -- might be a body continuation of a previous message
      return nil, "no status-line found"
   end

   local sl, err = parse_status_line(line)

   if sl == nil then
      return nil, err
   end

   if sl.type == HTTP_TYPE_REQUEST then
      http["type"] = sl["type"]
      http["method"] = sl["method"]
      http["uri"] = sl["uri"]
      http["version"] = sl["version"]
   else
      http["type"] = sl["type"]
      http["status"] = sl["status"]
      http["reason_phrase"] = sl["reason_phrase"]
      http["version"] = sl["version"]
   end

   -- parsing headers
   local headers = {}

   line, off = next_line(data, off)
   while line ~= nil do
      
      if #line == 0 then
	 break
      end
      
      local s, e = line:find(":", 1)
      if s ~= nil then
      	 local name = line:sub(1, s-1)
      	 local value = line:sub(e+2, #line)
      	 headers[name] = value
      end

      line, off = next_line(data, off)
   end

   http["headers"] = headers

   -- parsing body
   local body = data:sub(off)
   if #body > 0 then
      http["body"] = body
   end

   return http
end