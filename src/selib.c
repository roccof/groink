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
#include "debug.h"

void *check_object(lua_State *L, int arg, se_objtype_t type, char *name)
{
  se_obj_t *obj = NULL;

  obj = (se_obj_t *)luaL_checkudata(L, arg, name);
  myassert(obj != NULL);

  if(obj->type != type)
    luaL_error(L, "invalid '%s' object", name);

  return obj->object;
}

se_obj_t *se_pushobject(lua_State *L, void *object, se_objtype_t type, char *name)
{
 se_obj_t *obj = NULL;

 obj = (se_obj_t *)se_alloc_udata(L, sizeof(se_obj_t));
  luaL_getmetatable(L, name);
  lua_setmetatable(L, -2);

  obj->type = type;
  obj->object = object;

  return obj;
}

static int ro_index(lua_State *L)
{
  lua_gettable(L, -2);
  return 1;
}

static int ro_newindex(lua_State *L)
{
  luaL_error(L, "read-only table");
  return 0;
}

/* Set read-only the table at the top of the stack */
void se_setro(lua_State *L)
{
  myassert(lua_istable(L, -1));
  
  /* Metatable */
  lua_newtable(L);

  lua_pushstring(L, "__index");
  lua_pushcfunction(L, ro_index);
  lua_settable(L, -3); /* mt.__index = cfunc */

  lua_pushstring(L, "__newindex");
  lua_pushcfunction(L, ro_newindex);
  lua_settable(L, -3); /* mt.__newindex = cfunc */

  /* Set metatable to the table */
  lua_setmetatable(L, -2);
}

void *se_alloc_udata(lua_State *L, size_t len)
{
  void *p = NULL;

  p = lua_newuserdata(L, len);

  if(p == NULL)
    luaL_error(L, "user data not allocated");

  return p;
}

/* Print the Lua stack, useful for debug */
void stackDump (lua_State *L)
{
  int i;
  int top = lua_gettop(L);

  printf("\n----------[ stack dump ]----------\n\n");

  for (i=top; i>=1; i--)
  {
    int t = lua_type(L, i);
    printf("[%d]: ", i);
    switch (t)
      {
      case LUA_TSTRING:
	printf("'%s'", lua_tostring(L, i));
	break;
	
      case LUA_TBOOLEAN:
	printf(lua_toboolean(L, i) ? "true" : "false");
	break;
	
      case LUA_TNUMBER:
	printf("%g", lua_tonumber(L, i));
	break;
	
      default:
	printf("%s", lua_typename(L, t));
	break;
	
      }
    printf("\n");
  }
  printf("\n----------------------------------\n");
}
