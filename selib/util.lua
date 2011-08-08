-- Utility

local setmetatable = setmetatable
local pairs = pairs
local assert = assert
local error = error
local type = type

module("util")

function table_set_ro(t)
   assert(type(t) == "table")
   local proxy = {}
   local mt = { -- Create metatable
      __index = t,
      __newindex = function (t,k,v)
		      error("attempt to update a read-only table", 2)
		   end
   }
   setmetatable(proxy, mt)
   return proxy
end

function tablen(t)
   local count = 0
   
   assert(type(t) == "table")
   
   for k,v in pairs(t) do
      count = count + 1
   end
   return count
end

function table_contains(table, key)
   
   assert(type(table) == "table")
   assert(type(key) == "string" or type(key) == "number")
   
   for k,v in pairs(table) do
      if k == key then
	 return true
      end
   end
   return false
end

function strsplit(str, pattern)
   local list, pos = {}, 1;
   
   assert(pattern ~= "" and pattern ~= nil, "wrong delimiter!");
   
   while true do
      local f, l, m = str:find(pattern, pos);
      if f then
	 list[#list + 1] = str:sub(pos, f - 1);
	 pos = l + 1;
      else
	 list[#list + 1] = str:sub(pos);
	 break;
      end
   end
   return list;
end
