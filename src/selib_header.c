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

static int l_header_index(lua_State *L)
{
  luaL_Reg *m = NULL;
  header_t *h = NULL;
  proto_t *p = NULL;
  char *name = NULL;

  /* If the function is in the metatable return it */

  lua_getmetatable(L, -2);
  myassert(!lua_isnil(L, -1));

  lua_pushvalue(L, -2);
  lua_gettable(L, -2);

  if (!lua_isnil(L, -1) && lua_type(L, -1) == LUA_TFUNCTION)
    return 1; /* Return the function */

  /* Restore the stack */
  lua_settop(L, -3);

  /* Search the function in the protocol methods */

  name = (char *)luaL_checkstring(L, -1);
  h = check_header(L, -2);

  p = proto_get_byname(h->proto);
  myassert(p != NULL);

  if (p->methods == NULL)
    goto err;

  for (m=p->methods; m->name != NULL; m++) {
    if (strncmp(name, m->name, strlen(name)) == 0) {
      lua_pushcfunction(L, m->func);
      return 1;
    }
  }

 err:
  lua_pushnil(L);
  return 1;
}

static const struct luaL_reg header_methods[] = {
  {"rawdata", l_header_rawdata},
  {"len", l_header_len},
  {"proto", l_header_proto},
  {NULL, NULL}
};

void se_open_header(lua_State *L)
{
  luaL_newmetatable(L, SE_OBJ_NAME_HEADER);

  lua_pushstring(L, "__index");
  lua_pushcfunction(L, l_header_index);
  lua_settable(L, -3); /* metatable.__index = cfunc */

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
