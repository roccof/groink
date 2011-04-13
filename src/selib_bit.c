/*
 * Copyright (c) Denatured Ethyl Crew
 *
 * This file is part of GroinK.
 *
 * GroinK is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * GroinK is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GroinK.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include "selib.h"

static int l_bit_bwnot(lua_State *L)
{
  lua_pushnumber(L, (lua_Number)(~ (long)luaL_checknumber(L, 1)));
  return 1;
}

static int l_bit_bwand(lua_State *L)
{
  int size = lua_gettop(L);
  int i;
  long res = (long)luaL_checknumber(L, 1);
  
  for (i = 2; i <= size; i++)
    res &= (long)luaL_checknumber(L, i);

  lua_pushnumber(L, (lua_Number)res);
  
  return 1;
}

static int l_bit_bwor(lua_State *L)
{
  int size = lua_gettop(L);
  int i;
  long res = (long)luaL_checknumber(L, 1);
  
  for (i = 2; i <= size; i++)
    res |= (long)luaL_checknumber(L, i);

  lua_pushnumber(L, (lua_Number)res);
  
  return 1;
}

static int l_bit_bwxor(lua_State *L)
{
  int i;
  int size = lua_gettop(L);
  long res = (long)luaL_checknumber(L, 1);
  
  for (i = 2; i <= size; i++)
    res ^= (long)luaL_checknumber(L, i);

  lua_pushnumber(L, (lua_Number)res);
  
  return 1;
}

static int l_bit_lshift(lua_State *L)
{
  lua_pushnumber(L, (lua_Number)((long)luaL_checknumber(L, 1) << (long)luaL_checknumber(L, 2)));
  return 1;
}

static int l_bit_rshift(lua_State *L)
{
  lua_pushnumber(L, (lua_Number)((long)luaL_checknumber(L, 1) >> (long)luaL_checknumber(L, 2)));
  return 1;
}

static int l_bit_mod(lua_State *L)
{
  lua_pushnumber(L, (lua_Number)((long)luaL_checknumber(L, 1) % (long)luaL_checknumber(L, 2)));
  return 1;
}

static const struct luaL_reg bit_lib[] = {
  {"bwnot", l_bit_bwnot},
  {"bwand", l_bit_bwand},
  {"bwor", l_bit_bwor},
  {"bwxor", l_bit_bwxor},
  {"lshift", l_bit_lshift},
  {"rshift", l_bit_rshift},
  {"mod", l_bit_mod},
  {NULL, NULL}
};

void se_open_bit(lua_State *L)
{
  luaL_register(L, SELIB_BIT_NAME, bit_lib);
}
