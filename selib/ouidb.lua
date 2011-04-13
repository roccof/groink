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

-- ouidb.lua
-- asd

local core = require("core")
local io = require("io")
local find = string.find
local printf = core.printf
local pairs = pairs
local fatal = core.fatal
local print = print

module("ouidb")

local _ouidb = nil

local dbfile = core.selib_path().."oui_db.txt"

local function read_ouidb()
   if _ouidb == nil then
      local f = io.open(dbfile, "r")
      if f == nil then
	 -- no such file or permission denied
	 fatal("error while opening oui database file")
      else
	 _ouidb = {}
	 local line = f:read("*line")
	 while line ~= nil do
	    -- skip comment
	    if find(line, "^%s*#") == nil then
	       local _, _, oui, company = find(line, "([0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f])|([%w%s]+)")
	       if oui ~= nil and company ~= nil then
		  _ouidb[oui] = company
	       end
	    end
	    line = f:read("*line")
	 end
	 f:close()
      end
   end
   return _ouidb
end

local function is_valid(addr)
   if addr == nil or (addr == "00:00:00:00:00:00" or addr == "FF:FF:FF:FF:FF:FF") then
      return false
   end
   return true
end

function oui_from_addr(addr)
   if not is_valid(addr) then
      return nil;
   end
   -- load oui db
   local db = read_ouidb()
   local _, _, oui = find(addr, "([0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f])")
   if oui == nil then
      return nil
   else
      return db[oui]
   end
end


function oui_from_name(name)
   if name == nil then
      return nil
   end
   -- load oui db
   local db = read_ouidb()
   for oui, company in pairs(db) do
      if name == company then
	 return oui
      end
   end
   return nil
end