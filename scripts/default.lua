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

local corelib = require("core")

function proc_pkt(p)
   if p:contains_header(Proto.IPV6) then
      print("SRC-ADDR:", p:net_srcaddr())
      print("DST-ADDR:", p:net_dstaddr())
      print("-----------------------------------")
   end
end
