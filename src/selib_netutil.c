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
#include <lauxlib.h>

#include "netutil.h"
#include "selib.h"

static int l_netutil_is_ip_addr(lua_State *L)
{
  char *addr = (char *)luaL_checkstring(L, 1);
  lua_pushboolean(L, is_ip_addr(addr));

  return 1;
}

static int l_netutil_is_ether_addr(lua_State *L)
{
  char *addr = (char *)luaL_checkstring(L, 1);
  lua_pushboolean(L, is_ether_addr(addr));

  return 1;
}

static int l_netutil_is_ip_range_addr(lua_State *L)
{
  char *addr = (char *)luaL_checkstring(L, 1);
  lua_pushboolean(L, is_ip_range_addr_notation(addr));

  return 1;
}

static int l_netutil_is_ip_cidr_addr(lua_State *L)
{
  char *addr = (char *)luaL_checkstring(L, 1);
  lua_pushboolean(L, is_ip_cidr_addr_notation(addr));

  return 1;
}

static const struct luaL_reg netutil_lib[] =
{
  {"is_ip_addr", l_netutil_is_ip_addr},
  {"is_ether_addr", l_netutil_is_ether_addr},
  {"is_ip_range_addr", l_netutil_is_ip_range_addr},
  {"is_ip_cidr_addr", l_netutil_is_ip_cidr_addr},
  {NULL, NULL}
};

void se_open_netutil(lua_State *L)
{
  luaL_register(L, SELIB_NETUTIL_NAME, netutil_lib);
}
