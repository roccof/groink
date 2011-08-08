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

#include "protos_name.h"
#include "selib.h"

struct _grk_consts {
  char *name;
  const se_constant_t *values;
};

static const se_constant_t protos_const[] = {
  {"ETHER", { .str = PROTO_NAME_ETHER }, SE_TSTRING},
  {"ARP", { .str = PROTO_NAME_ARP }, SE_TSTRING},
  {"PPPOE", { .str = PROTO_NAME_PPPOE }, SE_TSTRING},
  {"RAW", { .str = PROTO_NAME_RAW }, SE_TSTRING},
  {"IPV4", { .str = PROTO_NAME_IPV4 }, SE_TSTRING},
  {"TCP", { .str = PROTO_NAME_TCP }, SE_TSTRING},
  {"UDP", { .str = PROTO_NAME_UDP }, SE_TSTRING},
  {"ICMP", { .str = PROTO_NAME_ICMP }, SE_TSTRING},
  {"IPV6", { .str = PROTO_NAME_IPV6 }, SE_TSTRING},
  {"ICMP6", { .str = PROTO_NAME_ICMP6 }, SE_TSTRING},
  {"HTTP", { .str = PROTO_NAME_HTTP }, SE_TSTRING},
  {"FTP", { .str = PROTO_NAME_FTP }, SE_TSTRING},
  {NULL, { .num = 0 }, SE_TNUMBER}
};

static const struct _grk_consts consts[] = {
  {"Proto", protos_const},
  {NULL, NULL}
};

void se_open_constants(lua_State *L)
{
  int i = 0, j = 0;

  for (i=0; consts[i].name!=NULL; i++) {
    se_constant_t *c = (se_constant_t *)consts[i].values;

    lua_newtable(L);

    for (j=0; c[j].name!=NULL; j++) {
      lua_pushstring(L, c[j].name);

      if (c[j].type == SE_TNUMBER)
	lua_pushnumber(L, c[j].value.num);
      else if (c[j].type == SE_TSTRING)
	lua_pushstring(L, c[j].value.str);
      else
	lua_pushboolean(L, c[j].value.num);

      lua_settable(L, -3);
    }
    
    /* Make table read-only */
    se_setro(L);

    lua_setglobal(L, consts[i].name);
  }
}
