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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <lua.h>
#include <lauxlib.h>
#include <unistd.h>

#include "base.h"
#include "globals.h"
#include "selib.h"
#include "debug.h"
/* #include "host.h" */

static int l_core_debug_mode(lua_State *L)
{
  lua_pushboolean(L, gbls->script_debug_mode);
  return 1;
}

static int l_core_iface(lua_State *L)
{
  lua_pushstring(L, gbls->iface);
  return 1;
}

static int l_core_mtu(lua_State *L)
{
  lua_pushnumber(L, gbls->mtu);
  return 1;
}

static int l_core_hwaddr(lua_State *L)
{
  if (gbls->link_addr != NULL)
    lua_pushstring(L, gbls->link_addr);
  else
    lua_pushnil(L);

  return 1;
}

static int l_core_netaddr(lua_State *L)
{
  if (gbls->net_addr != NULL)
    lua_pushstring(L, gbls->net_addr);
  else
    lua_pushnil(L);

  return 1;
}

static int l_core_netmask(lua_State *L)
{
  if (gbls->netmask != NULL)
    lua_pushstring(L, gbls->netmask);
  else
    lua_pushnil(L);

  return 1;
}

static int l_core_debug(lua_State *L)
{
  int i = 0;
  int args = 0;

  args = lua_gettop(L);

  lua_getfield(L, LUA_REGISTRYINDEX, SE_TRACEBACK);

  lua_getglobal(L, "string");
  myassert(!lua_isnil(L, -1));
  lua_getfield(L, -1, "format");
  myassert(!lua_isnil(L, -1));

  lua_replace(L, -2);

  for (i=0; i<args; i++)
    lua_pushvalue(L, i + 1);

  if (lua_pcall(L, args, 1, args + 1) != 0)
    lua_error(L);

  se_debug(lua_tostring(L, -1));

  return 0;
}

static int l_core_warning(lua_State *L)
{
  int i = 0;
  int args = 0;

  args = lua_gettop(L);

  lua_getfield(L, LUA_REGISTRYINDEX, SE_TRACEBACK);

  lua_getglobal(L, "string");
  myassert(!lua_isnil(L, -1));
  lua_getfield(L, -1, "format");
  myassert(!lua_isnil(L, -1));

  lua_replace(L, -2);

  for (i=0; i<args; i++)
    lua_pushvalue(L, i + 1);

  if (lua_pcall(L, args, 1, args + 1) != 0)
    lua_error(L);

  se_warning(lua_tostring(L, -1));

  return 0;
}

static int l_core_fatal(lua_State *L)
{
  int i = 0;
  int args = 0;

  args = lua_gettop(L);

  lua_getfield(L, LUA_REGISTRYINDEX, SE_TRACEBACK);

  lua_getglobal(L, "string");
  myassert(!lua_isnil(L, -1));
  lua_getfield(L, -1, "format");
  myassert(!lua_isnil(L, -1));

  lua_replace(L, -2);

  for (i=0; i<args; i++)
    lua_pushvalue(L, i + 1);

  if (lua_pcall(L, args, 1, args + 1) != 0)
    lua_error(L);

  luaL_error(L, lua_tostring(L, -1));

  return 0;
}

static int l_core_printf(lua_State *L)
{
  int i = 0;
  int args = 0;

  args = lua_gettop(L);

  lua_getfield(L, LUA_REGISTRYINDEX, SE_TRACEBACK);

  lua_getglobal(L, "string");
  myassert(!lua_isnil(L, -1));
  lua_getfield(L, -1, "format");
  myassert(!lua_isnil(L, -1));

  lua_replace(L, -2);

  for (i=0; i<args; i++)
    lua_pushvalue(L, i + 1);

  if (lua_pcall(L, args, 1, args + 1) != 0)
    lua_error(L);

  printf("%s", lua_tostring(L, -1));

  return 0;
}

static int l_core_getcwd(lua_State *L)
{
  char *cwd = getcwd(NULL, 0);
  lua_pushstring(L, cwd);
  free(cwd);
  return 1;
}

static int l_core_sleep(lua_State *L)
{
  _uint sec = (_uint)luaL_checkint(L, 1);
  sleep(sec);
  return 0;
}

static int l_core_usleep(lua_State *L)
{
  _uint usec = (_uint)luaL_checkint(L, 1);
  usleep(usec);
  return 0;
}

/* static int l_core_scanned_hosts(lua_State *L) */
/* { */
/*   Element *curr = NULL; */
/*   Host *host = NULL; */
/*   int i = 1; */

/*   lua_newtable(L); */

/*   LIST_FOREACH(curr, &(gbls->hosts)) */
/*     { */
/*       host = (Host *)list_elem_content(curr); */
      
/*       myassert(host != NULL); */

/*       lua_pushnumber(L, i++); */
/*       lua_newtable(L); */

/*       lua_pushstring(L, "net_addr"); */
/*       lua_pushstring(L, host->net_addr); */
/*       lua_settable(L, -3); */

/*       lua_pushstring(L, "hw_addr"); */
/*       lua_pushstring(L, host->hw_addr); */
/*       lua_settable(L, -3); */

/*       /\* Set the table in read-only *\/ */
/*       se_setro(L); */
      
/*       lua_settable(L, -3); */
/*     } */
  
/*   /\* Set the table in read-only *\/ */
/*   se_setro(L); */
  
/*   return 1; */
/* } */

/* static int l_core_dlt(lua_State *L) */
/* { */
/*   return 0; */
/* } */

static const struct luaL_reg core_lib[] = {
  {"debug_mode", l_core_debug_mode},
  {"iface", l_core_iface},
  {"mtu", l_core_mtu},
  {"hw_addr", l_core_hwaddr},
  {"net_addr", l_core_netaddr},
  {"netmask", l_core_netmask},
  {"debug", l_core_debug},
  {"warning", l_core_warning},
  {"fatal", l_core_fatal},
  {"printf", l_core_printf},
  {"getcwd", l_core_getcwd},
  {"sleep", l_core_sleep},
  {"usleep", l_core_usleep},
  /* {"scanned_hosts", l_core_scanned_hosts}, */
  /* {"dlt", l_core_dlt}, */
  {NULL, NULL}
};

void se_open_core(lua_State *L)
{
  luaL_register(L, SELIB_CORE_NAME, core_lib);
}
