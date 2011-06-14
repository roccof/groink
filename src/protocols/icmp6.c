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
#include "icmp6.h"
#include "debug.h"
#include "protos.h"
#include "protos_name.h"
#include "selib.h"

static int decode_icmp6(packet_t *p, const _uint8 *bytes, size_t len)
{
  icmp6_t *icmp = NULL;

  if (sizeof(icmp6_t) > len) {
    debug("malformed ICMPv6 header: invalid length");
    return call_decoder(PROTO_NAME_RAW, p, bytes, len);
  }
  
  icmp = (icmp6_t *)bytes;

  packet_append_header(p, PROTO_NAME_ICMP6, (void *)icmp, len);
  
  return DECODE_OK;
}

static int l_icmp6_type(lua_State *L)
{
  header_t *header = NULL;
  icmp6_t *icmp = NULL;  

  header = check_header(L, 1);
  icmp = (icmp6_t *)header->data;

  lua_pushnumber(L, icmp->type);

  return 1;
}

static int l_icmp6_code(lua_State *L)
{
  header_t *header = NULL;
  icmp6_t *icmp = NULL;  

  header = check_header(L, 1);
  icmp = (icmp6_t *)header->data;

  lua_pushnumber(L, icmp->code);
  return 1;
}

static int l_icmp6_cksum(lua_State *L)
{
  header_t *header = NULL;
  icmp6_t *icmp = NULL;  

  header = check_header(L, 1);
  icmp = (icmp6_t *)header->data;

  lua_pushnumber(L, ntohs(icmp->cksum));

  return 1;
}

static int l_icmp6_body(lua_State *L)
{
  header_t *header = NULL;
  icmp6_t *icmp = NULL;  

  header = check_header(L, 1);
  icmp = (icmp6_t *)header->data;

  switch (icmp->type) {
  
  /* case ICMP6_TYPE_ECHO_REQ: */
  /* case ICMP6_TYPE_ECHO_REP: */
  /*   process_echo(L, icmp, header->len); */
  /*   break; */
    
  /* case ICMP6_TYPE_DEST_UNREACH: */
  /*   lua_pushnil(L); */
  /*   break; */
    
  /* case ICMP6_TYPE_REDIRECT: */
  /*   process_redirect(L, icmp, header->len); */
  /*   break; */
    
  case ICMP6_TYPE_TIME_EXCEEDED:
  default:
    lua_pushnil(L);
  }

  return 1;
}

static const struct luaL_reg icmp6_methods[] = {
  {"type", l_icmp6_type},
  {"code", l_icmp6_code},
  {"cksum", l_icmp6_cksum},
  {"body", l_icmp6_body},
  {NULL, NULL}
};

void register_icmp6()
{
  proto_t *p = (proto_t *)safe_alloc(sizeof(proto_t));
  p->name = PROTO_NAME_ICMP6;
  p->longname = "Internet Control Message Protocol version 6";
  p->layer = L4;
  p->decoder = decode_icmp6;
  p->methods = (luaL_reg *)icmp6_methods;
  
  proto_register_byname(PROTO_NAME_ICMP6, p);
}
