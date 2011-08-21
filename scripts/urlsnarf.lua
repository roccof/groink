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

-- urlsnarf.lua
-- Url sniffer

local core = require("core")
local printf = core.printf
local urllib = require("urllib")
local httplib = require("http")

function proc_pkt(p)
   local payload = p:payload()

   if payload == nil then
      return
   end

   if payload.proto == Proto.HTTP then
      local http = httplib.parse_http(payload.data)
      local src url = nil, nil
      
      if http == nil or http.type == httplib.HTTP_TYPE_RESPONSE or
	 http.method == "POST" or http.headers["Host"] == nil then
	 return
      end
      
      url = "http://" .. http.headers["Host"] .. urllib.url_decode(http.uri)
      
      -- check src addr
      if netutil.is_ipv6_addr(p:net_srcaddr()) then
      	 src = "[".. p:net_srcaddr() .."]"
      else
      	 src = p:net_srcaddr()
      end
      
      printf("\n%s >> %s\n", src, url)
   end
end
