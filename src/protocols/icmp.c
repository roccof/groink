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
#include <string.h>
#include <lua.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "packet.h"
#include "decoder.h"
#include "icmp.h"
#include "debug.h"
#include "protos.h"
#include "protos_name.h"
#include "selib.h"

static int decode_icmp(packet_t *p, const _uint8 *bytes, size_t len)
{
  icmp_t *icmp = NULL;

  if (sizeof(icmp_t) > len) {
    decoder_add_error(p, "invalid ICMP header length");
    return call_decoder(PROTO_NAME_RAW, p, bytes, len);
  }

  icmp = (icmp_t *)bytes;
  packet_append_header(p, PROTO_NAME_ICMP, (void *)icmp, len);
  
  return DECODE_OK;
}

static int l_dissect_icmp(lua_State *L)
{
  header_t *header = NULL;
  icmp_t *icmp = NULL;
  icmp_body_t *body = NULL;
  struct in_addr gw;

  header = check_header(L, 1);
  icmp = (icmp_t *)header->data;

  lua_newtable(L);

  lua_pushstring(L, "type");
  lua_pushnumber(L, icmp->type);
  lua_settable(L, -3);

  lua_pushstring(L, "code");
  lua_pushnumber(L, icmp->code);
  lua_settable(L, -3);

  lua_pushstring(L, "cksum");
  lua_pushnumber(L, ntohs(icmp->cksum));
  lua_settable(L, -3);

  lua_pushstring(L, "body");
  
  switch (icmp->type) {
  
  case ICMP_TYPE_ECHO:
  case ICMP_TYPE_ECHOREPLY:
    body = (icmp_body_t *)(icmp + 1);
    
    lua_newtable(L);
    
    lua_pushstring(L, "id");
    lua_pushnumber(L, htons(body->id));
    lua_settable(L, -3);
    
    lua_pushstring(L, "seq");
    lua_pushnumber(L, htons(body->seq));
    lua_settable(L, -3);
    
    se_setro(L);
    
    break;
    
  case ICMP_TYPE_REDIRECT:
    
    if (header->len - ICMP_HDR_LEN < 4) {
      lua_pushnil(L);
      break;
    }
    
    lua_newtable(L);
    
    gw = (*(struct in_addr *)(icmp + 1));
    
    lua_pushstring(L, "gw_addr");
    lua_pushstring(L, inet_ntoa(gw));
    lua_settable(L, -3);

    se_setro(L);

    break;
    
  case ICMP_TYPE_DEST_UNREACH:
  case ICMP_TYPE_TIME_EXCEEDED:
  default:
    lua_pushnil(L);
  }

  lua_settable(L, -3);

  se_setro(L);

  return 1;
}

void register_icmp()
{
  proto_t *p = (proto_t *)safe_alloc(sizeof(proto_t));
  p->name = PROTO_NAME_ICMP;
  p->longname = "Internet Control Message Protocol";
  p->layer = L4;
  p->decoder = decode_icmp;
  p->dissect = l_dissect_icmp;
  
  proto_register_byname(PROTO_NAME_ICMP, p);
}
