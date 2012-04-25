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
#include "protos_name.h"
#include "protos.h"
#include "http.h"
#include "selib.h"

static int decode_http(packet_t *p, const _uint8 *bytes, size_t len)
{
  header_t *h = packet_append_header(p, PROTO_NAME_HTTP, (void *)bytes, len);
  packet_set_payload(p, h);

  return DECODE_OK;
}

static void find_auth_info(lua_State *L, header_t *h)
{
  /* _uchar *data = h->data; */
  
  /* if (strncmp("GET", data, 3) == 0) { */
  /*   /\* Process GET *\/ */
  /* } else if (strncmp("POST", data, 4) == 0) { */
  /*   /\* Process POST *\/ */
  /* } */
}

static int l_dissect_http(lua_State *L)
{
  header_t *h = check_header(L, 1);

  lua_newtable(L);

  lua_pushstring(L, "data");
  lua_pushlstring(L, (const char *)h->data, h->len);
  lua_settable(L, -3);

  lua_pushstring(L, "len");
  lua_pushnumber(L, h->len);
  lua_settable(L, -3);

  find_auth_info(L, h);

  se_setro(L);

  return 1;
}

void register_http()
{
  proto_t *p = (proto_t *)safe_alloc(sizeof(proto_t));
  p->name = PROTO_NAME_HTTP;
  p->longname = "Hypertext Transfer Protocol";
  p->layer = L5;
  p->decoder = decode_http;
  p->dissect = l_dissect_http;
  
  proto_register_byname(PROTO_NAME_HTTP, p);
  proto_register_byport(80, p);
  proto_register_byport(8080, p);
}
