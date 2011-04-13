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
-- asd

local core = require("core")
local tobyte = string.byte
local printf = core.printf

module("dump")

local maxbytes = 16;

local function print_hex_line(data, line)
   for i=1, maxbytes, 1 do
      local byte = tobyte(data, ((line - 1) * maxbytes) + i)
      -- if byte is nil print white line
      if byte == nil then
	 printf(" ")
      else
	 printf("%02x ", byte)
      end
   end
end

local function print_ascii_line(data, line)
   for i=1, maxbytes, 1 do
      local byte = tobyte(data, ((line - 1) * maxbytes) + i)
      
      -- if byte is nil the data is ended
      if byte == nil then
	 return
      end
      
      if byte > 31 and byte < 127 then
	 printf("%c", byte)
      else
	 printf(".")
      end
   end
end

local function dump(data, len, hex, ascii)
   local tot_line = len/maxbytes;
   
   -- scan all line
   for line=1, tot_line+1, 1 do
      
      -- print the first byte of the line
      printf("%08x ", ((line -1) * maxbytes))
      
      -- print line in hex
      if hex then
	 print_hex_line(data, line)
	 printf(" ")
      end
      
      -- print line in stampable ascii character
      if ascii then
	 print_ascii_line(data, line)
      end
      
      printf("\n")
   end
end

function hex_ascii_dump(data, len)
   dump(data, len, true, true)
end

function hex_dump(data, len)
   dump(data, len, true, false)
end

function ascii_dump(data, len)
   dump(data, len, false, true)
end