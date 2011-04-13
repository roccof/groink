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

-- script_engine.lua
-- This script is called from 'script_engine.c' and set an enviroment for 
-- script execution.

-- Registry key
local SE_ARGV = "SE_ARGV"
local SE_ARGC = "SE_ARGC"
local SE_PROC_PKT = "SE_PROC_PKT"
local SE_INIT = "SE_INIT"
local SE_CLEANUP = "SE_CLEANUP"

local _G = _G

local loadfile = loadfile
local package = package
local setfenv = setfenv
local error = error
local assert = assert
local type = type
local rawget = rawget
local rawset = rawset
local getinfo = getinfo

local D = require("debug")
local getinfo = debug.getinfo
local _R = D.getregistry()

local string = require("string")
local format = string.format

local coroutine = require("coroutine")
local create = coroutine.create
local resume = coroutine.resume

-- The name of the script that will be executed and the 
-- selib path are passed as argument
local script, selib = ...

do -- Append all .lua file into selib dir to the Lua search path
   package.path = package.path..";"..selib.."?.lua"
end

-- Checks uses of undeclared global variables.
-- All global variables must be 'declared' through a regular assignment
-- (even assigning nil will do) in a main chunk before being used
-- anywhere or assigned to inside a function.
-- Borrowed from strict.lua of Lua source.
do
   local mt = getmetatable(_G)
   if mt == nil then
      mt = {}
      setmetatable(_G, mt)
   end
   
   mt.__declared = {}
   
   local function what ()
      local d = getinfo(3, "S")
      return d and d.what or "C"
   end
   
   mt.__newindex = function (t, n, v)
		      if not mt.__declared[n] then
			 local w = what()
			 if w ~= "main" and w ~= "C" then
			    error("assign to undeclared variable '"..n.."'", 2)
			 end
			 mt.__declared[n] = true
		      end
		      rawset(t, n, v)
		   end
   
   mt.__index = function (t, n)
		   if not mt.__declared[n] and what() ~= "C" then
		      error("variable '"..n.."' is not declared", 2)
		   end
		   return rawget(t, n)
		end
end

local function table_contains(table, key)
   assert(type(table) == "table")
   assert(type(key) == "string" or type(key) == "number")

   for k,v in pairs(table) do
      if k == key then
	 return true
      end
   end
   return false
end

-- Env table
local env = {
   SCRIPT = script,
   SELIB_DIR = selib,
   _argv = _R[SE_ARGV],
   _argc = _R[SE_ARGC]
}
setmetatable(env, { __index = _G });

-- Initialize the engine
local function init()

   -- save selib directory into the registry
   _R["SELIB_DIR"] = selib

   local func, err = loadfile(script)

   if func then
      setfenv(func, env)

      local function init_engine()
	 func() -- load globals

	 if not table_contains(env, "proc_pkt") then
	    error("unable to find 'proc_pkt' function in the script", 0)
	 end
	 
	 _R[SE_PROC_PKT] = env.proc_pkt

	 if table_contains(env, "init") then
	    _R[SE_INIT] = env.init
	 else
	    _R[SE_INIT] = nil
	 end

	 if table_contains(env, "cleanup") then
	    _R[SE_CLEANUP] = env.cleanup
	 else
	    _R[SE_CLEANUP] = nil
	 end
      end

      setfenv(init_engine, env);
      
      -- Create and run the coroutine
      local co = create(init_engine)
      local status, ret = resume(co)

      if not status then
	 error(format("%s", ret), 0)
      end
   else
      error(err, 0)
   end
end

init()