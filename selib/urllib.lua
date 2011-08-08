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

-- urllib.lua
-- URL utilities

local string = require("string")
local tonumber = tonumber

module("urllib")

-- Stolen from: http://lua-users.org/wiki/StringRecipes
function url_decode(str)
   str = string.gsub (str, "+", " ")
   str = string.gsub (str, "%%(%x%x)",
		      function(h) return string.char(tonumber(h,16)) end)
   str = string.gsub (str, "\r\n", "\n")
   return str
end

-- Stolen from: http://lua-users.org/wiki/StringRecipes
function url_encode(str)
   if (str) then
      str = string.gsub (str, "\n", "\r\n")
      str = string.gsub (str, "([^%w ])",
			 function (c) return string.format ("%%%02X", string.byte(c)) end)
      str = string.gsub (str, " ", "+")
   end
   return str	
end
