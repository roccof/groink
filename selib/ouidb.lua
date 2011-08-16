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

local iolib = require("io")
local stringlib = require("string")
local find = stringlib.find
local pairs = pairs
local corelib = require("core")
local printf = corelib.printf
local fatal = corelib.fatal
local D = require("debug")
local _R = D.getregistry()

module("ouidb")

local _ouidb = nil
local dbfile = _R["SELIB_DIR"].."oui_db.txt"
local dbentry_regex = "([0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f])|([%w%s]+)"
local oui_regex = "([0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f])"

local function read_ouidb()
   if _ouidb == nil then
      local f = iolib.open(dbfile, "r")
      if f == nil then
	 -- no such file or permission denied
	 fatal("error while opening oui database file")
      else
	 _ouidb = {}
	 local line = f:read("*line")
	 while line ~= nil do
	    -- skip comment
	    if find(line, "^%s*#") == nil then
	       local _, _, oui, company = find(line, dbentry_regex)
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
   if addr == nil or 
      (addr == "00:00:00:00:00:00" or addr == "FF:FF:FF:FF:FF:FF") then
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
   local _, _, oui = find(addr, oui_regex)
   if oui == nil then
      return nil
   else
      return db[oui:upper()]
   end
end

function oui_from_name(name)
   if name == nil then
      return nil
   end
   -- load oui db
   local db = read_ouidb()
   for oui, company in pairs(db) do
      if name:lower() == company:lower() then
	 return oui
      end
   end
   return nil
end