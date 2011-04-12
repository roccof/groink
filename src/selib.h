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
#ifndef GROINK_SELIB_H
#define GROINK_SELIB_H

#include <lua.h>

#include "packet.h"

/* Key in Lua registry */
#define SE_TRACEBACK "SE_TRACEBACK"
#define SE_ARGV "SE_ARGV"
#define SE_ARGC "SE_ARGC"
#define SE_PROC_PKT "SE_PROC_PKT"
#define SE_CLEANUP "SE_CLEANUP"
#define SE_INIT "SE_INIT"

/* Libraries name */
#define SELIB_BIT_NAME "bit"
#define SELIB_CORE_NAME "core"

/* Objects name */
#define SE_OBJ_NAME_PACKET "Packet"
#define SE_OBJ_NAME_HEADER "Header"

/* Object type */
typedef enum _grk_se_obj_type {
  SE_OBJ_TYPE_PACKET,
  SE_OBJ_TYPE_HEADER
} se_objtype_t;

/* Definition of a constant name/value pair */
typedef struct _grk_se_constant {
  const char *name;
  int value;
} se_constant_t;

/* User data object */
typedef struct _grk_se_obj_udata {
  se_objtype_t type;  /* Object type */
  void *object;       /* Object data */
} se_obj_t;

void *se_alloc_udata(lua_State *L, size_t len);
void se_setro(lua_State *L);
void *check_object(lua_State *L, int arg, se_objtype_t type, char *name);
se_obj_t *se_pushobject(lua_State *L, void *object, se_objtype_t type, char *name);

header_t *check_header(lua_State *L, int arg);

void se_open_packet(lua_State *L);
void se_open_header(lua_State *L);

void stackDump (lua_State *L);

#endif /* GROINK_SELIB_H */
