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
-- This script dissect packet and show username and password.

local core = require("core")
local printf = core.printf
local fatal = core.fatal
local netutil = require("netutil")

local addr = nil

function proc_pkt(p)
  if p:net_srcaddr() == addr or p:net_dstaddr() == addr then
      p:set_drop(true)  -- Drop the packet
   end
end

function init()
   addr = _argv["host"]
   
   if addr == nil or not netutil.is_ip_addr(addr) then
      fatal("enter a valid host address to be isolate")
   end
   
   printf("Isolating %s...\n", addr)
end