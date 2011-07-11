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
#include "netutil.h"

static int decode_icmp6(packet_t *p, const _uint8 *bytes, size_t len)
{
  icmp6_t *icmp = NULL;

  if (sizeof(icmp6_t) > len) {
    decoder_add_error(p, "invalid ICMPv6 header length");
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

static void process_echo(lua_State *L, icmp6_t *icmp, unsigned int len)
{
  icmp6_echo_t *echo = NULL;

  if (len < sizeof(icmp6_echo_t)) {
    debug("malformed ICMPv6 echo body: invalid length");
    lua_pushnil(L);
  }

  echo = (icmp6_echo_t *)(icmp + 1);

  lua_newtable(L);
  
  lua_pushstring(L, "id");
  lua_pushnumber(L, htons(echo->id));
  lua_settable(L, -3);

  lua_pushstring(L, "seq");
  lua_pushnumber(L, htons(echo->seq));
  lua_settable(L, -3);
}

static void process_pkt_too_big(lua_State *L, icmp6_t *icmp, unsigned int len)
{
  if (len < sizeof(_uint32)) {
    debug("malformed ICMPv6 packet too big body: invalid length");
    lua_pushnil(L);
  }

  lua_newtable(L);
  
  lua_pushstring(L, "mtu");
  lua_pushnumber(L, htonl(*((_uint32 *)(icmp + 1))));
  lua_settable(L, -3);
}

static void process_param_problem(lua_State *L, icmp6_t *icmp, unsigned int len)
{
  if (len < sizeof(_uint32)) {
    debug("malformed ICMPv6 parameter problem body: invalid length");
    lua_pushnil(L);
  }

  lua_newtable(L);
  
  lua_pushstring(L, "pointer");
  lua_pushnumber(L, htonl(*((_uint32 *)(icmp + 1))));
  lua_settable(L, -3);
}

static void process_neigh_sol(lua_State *L, icmp6_t *icmp, unsigned int len)
{
  icmp6_neigh_sol_t *b = NULL;
  char *addr = NULL;

  if (len < sizeof(icmp6_neigh_sol_t)) {
    debug("malformed ICMPv6 neigh solocit body: invalid length");
    lua_pushnil(L);
  }

  b = (icmp6_neigh_sol_t *)icmp + 1;
  addr = ipv6_addr_ntoa(b->target_addr);

  lua_newtable(L);
  
  lua_pushstring(L, "target_addr");
  lua_pushstring(L, addr);
  lua_settable(L, -3);

  free(addr);
}

static void process_router_adv(lua_State *L, icmp6_t *icmp, unsigned int len)
{
  icmp6_router_adv_t *b = NULL;

  if (len < sizeof(icmp6_router_adv_t)) {
    debug("malformed ICMPv6 router adv body: invalid length");
    lua_pushnil(L);
  }

  b = (icmp6_router_adv_t *)icmp + 1;

  lua_newtable(L);
  
  lua_pushstring(L, "cur_hop_limit");
  lua_pushnumber(L, b->cur_hop_limit);
  lua_settable(L, -3);

  lua_pushstring(L, "managed_addr_conf");
  lua_pushboolean(L, ((b->flags & ICMP6_ROUTER_ADV_F_MANAGED) == ICMP6_ROUTER_ADV_F_MANAGED));
  lua_settable(L, -3);

  lua_pushstring(L, "other_addr_conf");
  lua_pushboolean(L, ((b->flags & ICMP6_ROUTER_ADV_F_OTHER) == ICMP6_ROUTER_ADV_F_OTHER));
  lua_settable(L, -3);

  lua_pushstring(L, "router_lifetime");
  lua_pushnumber(L, htons(b->router_lifetime));
  lua_settable(L, -3);

  lua_pushstring(L, "reachable_time");
  lua_pushnumber(L, htonl(b->reachable_time));
  lua_settable(L, -3);

  lua_pushstring(L, "retrans_timer");
  lua_pushnumber(L, htonl(b->retrans_timer));
  lua_settable(L, -3);
}

static int l_icmp6_body(lua_State *L)
{
  header_t *header = NULL;
  icmp6_t *icmp = NULL;  

  header = check_header(L, 1);
  icmp = (icmp6_t *)header->data;

  switch (icmp->type) {
  
  case ICMP6_TYPE_ECHO_REQ:
  case ICMP6_TYPE_ECHO_REP:
    process_echo(L, icmp, (header->len - ICMP6_HDR_LEN));
    break;

  case ICMP6_TYPE_PKT_TOO_BIG:
    process_pkt_too_big(L, icmp, (header->len - ICMP6_HDR_LEN));
    break;

  case ICMP6_TYPE_PARAM_PROB:
    process_param_problem(L, icmp, (header->len - ICMP6_HDR_LEN));
    break;

  case ICMP6_TYPE_NEIGH_SOL:
    process_neigh_sol(L, icmp, (header->len - ICMP6_HDR_LEN));
    break;

  case ICMP6_TYPE_ROUTER_ADV:
    process_router_adv(L, icmp, (header->len - ICMP6_HDR_LEN));
    break;

  case ICMP6_TYPE_NEIGH_ADV:
    break;

  case ICMP6_TYPE_REDIRECT:
    break;

  case ICMP6_TYPE_ROUTER_RENUM:
    break;

  case ICMP6_TYPE_ROUTER_SOL:
  case ICMP6_TYPE_DEST_UNREACH:
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
  /* {"opt", l_icmp6_opt}, */
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
