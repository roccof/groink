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

-- dump.lua
-- this script prints the packets in esadecimal, ascii or both format

local dumplib = require("dump")
local corelib = require("core")
local printf = corelib.printf

local type = nil

function proc_pkt(p)	      
   printf("Got packet of %d byte(s)\n", p:len())
   if type == "hex" then
      dumplib.hex(p:data(), p:len())
   elseif type == "ascii" then
      dumplib.ascii(p:data(), p:len())
   else
      dumplib.hex_ascii(p:data(), p:len())
   end
   printf("\n")
end

function init()
   corelib.set_pktdecoding(false)
   type = _argv["type"]
end
