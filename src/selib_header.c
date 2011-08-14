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
#include <string.h>

#include "selib.h"
#include "packet.h"
#include "debug.h"
#include "protos.h"

header_t *check_header(lua_State *L, int arg)
{
   return (header_t *)check_object(L, arg, SE_OBJ_TYPE_HEADER, SE_OBJ_NAME_HEADER);
}

static int l_header_rawdata(lua_State *L)
{
  header_t *h = check_header(L, -1);
  lua_pushlstring(L, (const char *)h->data, h->len);
  return 1;
}

static int l_header_len(lua_State *L)
{
  header_t *h = check_header(L, -1);
  lua_pushnumber(L, h->len);
  return 1;
}

static int l_header_proto(lua_State *L)
{
  header_t *h = check_header(L, -1);
  lua_pushstring(L, h->proto);
  return 1;
}

static int l_header_dissect(lua_State *L)
{
  proto_t * p = NULL;
  header_t *h = check_header(L, -1);

  p = proto_get_byname(h->proto);
  myassert(p != NULL);

  if (p->dissect == NULL) {
    lua_pushnil(L);
    return 1;
  }

  /* Stack pos 2: traceback function */
  lua_getfield(L, LUA_REGISTRYINDEX, SE_TRACEBACK);

  /* Stack pos 3: dissect callback function */
  lua_pushcfunction(L, p->dissect);

  /* Stack pos 4: header userdata */
  lua_pushvalue(L, 1);

  if (lua_pcall(L, 1, 1, 2) != 0) {
    lua_error(L);
    return 0;
  }

  return 1;
}

static int l_header_tostring(lua_State *L)
{
  header_t *h = check_header(L, -1);
  proto_t *p = proto_get_byname(h->proto);

  if (p == NULL)
    lua_pushfstring(L, "Header: %p", lua_touserdata(L, -1));
  else
    lua_pushfstring(L, "Header[%s]: %p", p->longname, lua_touserdata(L, -1));
  return 1;
}

static int l_header_gc(lua_State *L)
{
  /* header_t *h = check_header(L, -1); */
  return 0;
}

static int l_header_eq(lua_State *L)
{
  /* header_t *h = check_header(L, -1); */
  /* TODO */
  return 0;
}

static const struct luaL_reg header_methods[] = {
  {"rawdata", l_header_rawdata},
  {"len", l_header_len},
  {"proto", l_header_proto},
  {"dissect", l_header_dissect},
  {NULL, NULL}
};

void se_open_header(lua_State *L)
{
  luaL_newmetatable(L, SE_OBJ_NAME_HEADER);

  lua_pushstring(L, "__index");
  lua_pushvalue(L, -2);
  lua_settable(L, -3); /* metatable.__index = metatable */

  lua_pushstring(L, "__tostring");
  lua_pushcfunction(L, l_header_tostring);
  lua_settable(L, -3); /* metatable.__tostring = cfunc */

  lua_pushstring(L, "__gc");
  lua_pushcfunction(L, l_header_gc);
  lua_settable(L, -3); /* metatable.__gc = cfunc */

  lua_pushstring(L, "__eq");
  lua_pushcfunction(L, l_header_eq);
  lua_settable(L, -3); /* metatable.__eq = cfunc */
  
  /* Setting object methods */
  luaL_register(L, NULL, header_methods);
}
