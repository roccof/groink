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
#include <arpa/inet.h>

#include "protos_name.h"
#include "protos.h"
#include "sll.h"
#include "selib.h"

static int decode_sll(packet_t *p, const _uint8 *bytes, size_t len)
{
  sll_t *sll = (sll_t *)bytes;

  packet_append_header(p, PROTO_NAME_SLL, (void *)sll, SLL_HDR_LEN);

  return DECODE_OK;
}

static int l_dissect_sll(lua_State *L)
{
  header_t *h = NULL;
  sll_t *sll = NULL;

  h = check_header(L, 1);
  sll = (sll_t *)h->data;

  lua_newtable(L);

  lua_pushstring(L, "pkt_type");
  lua_pushnumber(L, ntohs(sll->type));
  lua_settable(L, -3);

  lua_pushstring(L, "arp_hdr");
  lua_pushnumber(L, ntohs(sll->arp_hdr));
  lua_settable(L, -3);

  lua_pushstring(L, "addr_len");
  lua_pushnumber(L, ntohs(sll->addr_len));
  lua_settable(L, -3);

  lua_pushstring(L, "addr");
  lua_pushlstring(L, (char *)sll->addr, 8);
  lua_settable(L, -3);

  lua_pushstring(L, "proto_type");
  lua_pushnumber(L, ntohs(sll->proto));
  lua_settable(L, -3);

  se_setro(L);

  return 1;
}

void register_sll()
{
  proto_t *p = (proto_t *)safe_alloc(sizeof(proto_t));
  p->name = PROTO_NAME_SLL;
  p->longname = "Linux Cooked";
  p->layer = L2;
  p->decoder = decode_sll;
  p->dissect = l_dissect_sll;
  
  proto_register_byname(PROTO_NAME_SLL, p);
}
