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

-- default.lua
-- Default script. This script is called by default if there isn't specified one.
-- This script dissect the payload and show username and password.

local diss = require("dissector")
local core = require("core")
local printf = core.printf
local netutil = require("netutil")

function proc_pkt(p)
   local info, usr, pwd = nil, nil, nil

   local payload = p:payload()

   if payload == nil then
      return
   end

   -- dissect the payload
   if payload.proto == Proto.HTTP then
      info, usr, pwd = diss.dissect_http(p)
   elseif payload.proto == Proto.FTP then
      info, usr, pwd = diss.dissect_ftp(p)
   end
   
   if info ~= nil then
      local dst, port = nil, ""

      -- check dst addr
      if netutil.is_ipv6_addr(p:net_dstaddr()) then
      	 dst = "[".. p:net_dstaddr() .."]"
      else
      	 dst = p:net_dstaddr()
      end

      -- check port
      if p:dst_port() > 0 then
	 port = ":" .. p:dst_port()
      end
      
      printf("\n%s%s >> %s\n|_user: %s\n|_passwd: %s\n", dst, port, info, usr, pwd)
   end
end
