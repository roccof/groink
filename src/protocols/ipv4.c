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
#include <arpa/inet.h>

#include "base.h"
#include "packet.h"
#include "ipv4.h"
#include "protos.h"
#include "protos_name.h"
#include "netutil.h"
#include "selib.h"

static int decode_ipv4(packet_t *p, const _uint8 *bytes, size_t len)
{
  ipv4_t *ip = NULL;
  header_t *h = NULL;

  if (len < sizeof(ipv4_t)) {
    debug("malformed IPv4 header: invalid length");
    return call_decoder(PROTO_NAME_RAW, p, bytes, len);
  }

  ip = (ipv4_t *)bytes;

  /* Control if IHL is valid, min 20 bytes */
  if (IPV4_HDR_LEN(ip) < sizeof(ipv4_t)) {
    debug("bad IPv4 header size");
    return call_decoder(PROTO_NAME_RAW, p, bytes, len);
  }

  h = packet_append_header(p, PROTO_NAME_IPV4, (void *)ip, IPV4_HDR_LEN(ip));
  
  p->net_srcaddr = ip_addr_ntoa(ip->src_addr);
  p->net_dstaddr = ip_addr_ntoa(ip->dest_addr);
  
  /* Control VERSION */
  if (IPV4_VERS(ip) != 4) {
    debug("packet decoding: bad IPv4 VERSION (%d)", IPV4_VERS(ip));
    ADD_ERROR(h, ERR_IPV4_BAD_VERSION);
  }

  /* switch (ip->proto) { */
  /* case IPV4_PROTO_TCP: */
  /*   return call_decoder(PROTO_TCP, p, (bytes + IPV4_HDR_LEN(ip)), 
       (len - IPV4_HDR_LEN(ip))); */
    
  /* case IPV4_PROTO_UDP: */
  /*   return call_decoder(PROTO_UDP, p, (bytes + IPV4_HDR_LEN(ip)), 
       (len - IPV4_HDR_LEN(ip))); */
    
  /* case IPV4_PROTO_ICMP: */
  /*   return call_decoder(PROTO_ICMP, p, (bytes + IPV4_HDR_LEN(ip)), 
       (len - IPV4_HDR_LEN(ip))); */
    
  /* default: */
  /*   /\* Unknown layer 4 protocol *\/ */
  /*   return call_decoder(PROTO_RAW, p, (bytes + IPV4_HDR_LEN(ip)), 
       (len - IPV4_HDR_LEN(ip))); */
  /* } */
  return DECODE_OK;
}

static int l_ipv4_ihl(lua_State *L)
{
  header_t *header = NULL;
  ipv4_t *ip = NULL;
  
  header = check_header(L, 1);
  ip = (ipv4_t *)header->data;

  lua_pushnumber(L, IPV4_IHL(ip));

  return 1;
}

static int l_ipv4_version(lua_State *L)
{
  header_t *header = NULL;
  ipv4_t *ip = NULL;
  
  header = check_header(L, 1);
  ip = (ipv4_t *)header->data;

  lua_pushnumber(L, IPV4_VERS(ip));

  return 1;
}

static int l_ipv4_tos(lua_State *L)
{
  header_t *header = NULL;
  ipv4_t *ip = NULL;
  
  header = check_header(L, 1);
  ip = (ipv4_t *)header->data;

  lua_pushnumber(L, ip->tos);

  return 1;
}

static int l_ipv4_totlen(lua_State *L)
{
  header_t *header = NULL;
  ipv4_t *ip = NULL;
  
  header = check_header(L, 1);
  ip = (ipv4_t *)header->data;

  lua_pushnumber(L, ntohs(ip->len));

  return 1;
}

static int l_ipv4_id(lua_State *L)
{
  header_t *header = NULL;
  ipv4_t *ip = NULL;
  
  header = check_header(L, 1);
  ip = (ipv4_t *)header->data;

  lua_pushnumber(L, ntohs(ip->id));

  return 1;
}

static int l_ipv4_frag_offset(lua_State *L)
{
  header_t *header = NULL;
  ipv4_t *ip = NULL;
  
  header = check_header(L, 1);
  ip = (ipv4_t *)header->data;

  lua_pushnumber(L, (ntohs(ip->frag_offset) & IPV4_FRAG));

  return 1;
}

static int l_ipv4_df(lua_State *L)
{
  header_t *header = NULL;
  ipv4_t *ip = NULL;
  
  header = check_header(L, 1);
  ip = (ipv4_t *)header->data;

  lua_pushboolean(L, ((ntohs(ip->frag_offset) & IPV4_DF) == IPV4_DF));

  return 1;
}

static int l_ipv4_mf(lua_State *L)
{
  header_t *header = NULL;
  ipv4_t *ip = NULL;
  
  header = check_header(L, 1);
  ip = (ipv4_t *)header->data;

  lua_pushboolean(L, ((ntohs(ip->frag_offset) & IPV4_MF) == IPV4_MF));

  return 1;
}

static int l_ipv4_rf(lua_State *L)
{
  header_t *header = NULL;
  ipv4_t *ip = NULL;
  
  header = check_header(L, 1);
  ip = (ipv4_t *)header->data;

  lua_pushboolean(L, ((ntohs(ip->frag_offset) & IPV4_RF) == IPV4_RF));

  return 1;
}

static int l_ipv4_ttl(lua_State *L)
{
  header_t *header = NULL;
  ipv4_t *ip = NULL;
  
  header = check_header(L, 1);
  ip = (ipv4_t *)header->data;

  lua_pushnumber(L, ip->ttl);

  return 1;
}

static int l_ipv4_protocol(lua_State *L)
{
  header_t *header = NULL;
  ipv4_t *ip = NULL;
  
  header = check_header(L, 1);
  ip = (ipv4_t *)header->data;

  lua_pushnumber(L, ip->proto);

  return 1;
}

static int l_ipv4_checksum(lua_State *L)
{
  header_t *header = NULL;
  ipv4_t *ip = NULL;
  
  header = check_header(L, 1);
  ip = (ipv4_t *)header->data;

  lua_pushnumber(L, ntohs(ip->checksum));

  return 1;
}

static int l_ipv4_src_addr(lua_State *L)
{
  header_t *header = NULL;
  ipv4_t *ip = NULL;
  char *addr = NULL;
  
  header = check_header(L, 1);
  ip = (ipv4_t *)header->data;

  addr = ip_addr_ntoa(ip->src_addr);
  lua_pushstring(L, addr);
  free(addr);

  return 1;
}

static int l_ipv4_dst_addr(lua_State *L)
{
  header_t *header = NULL;
  ipv4_t *ip = NULL;
  char *addr = NULL;
  
  header = check_header(L, 1);
  ip = (ipv4_t *)header->data;

  addr = ip_addr_ntoa(ip->dest_addr);
  lua_pushstring(L, addr);
  free(addr);

  return 1;
}

static const struct luaL_reg ip_methods[] = {
  {"ihl", l_ipv4_ihl},
  {"version", l_ipv4_version},
  {"tos", l_ipv4_tos},
  /* {"tos_precedence", l_ipv4_tos_prec}, */
  /* {"tos_delay", l_ipv4_tos_delay}, */
  /* {"tos_throughput", l_ipv4_tos_through}, */
  /* {"tos_relibility", l_ipv4_tos_rel}, */
  {"totlen", l_ipv4_totlen},
  {"id", l_ipv4_id},
  {"frag_offset", l_ipv4_frag_offset},
  {"df", l_ipv4_df},
  {"mf", l_ipv4_mf},
  {"rf", l_ipv4_rf},
  {"ttl", l_ipv4_ttl},
  {"protocol", l_ipv4_protocol},
  {"checksum", l_ipv4_checksum},
  {"src_addr", l_ipv4_src_addr},
  {"dst_addr", l_ipv4_dst_addr},
  /* {"options", l_ipv4_options}, */
  {NULL, NULL}
};

void register_ipv4()
{
  proto_t *p = (proto_t *)safe_alloc(sizeof(proto_t));
  p->name = PROTO_NAME_IPV4;
  p->longname = "Internet Protocol version 4";
  p->layer = L3;
  p->decoder = decode_ipv4;
  p->methods = (luaL_reg *)ip_methods;
  
  proto_register_byname(PROTO_NAME_IPV4, p);
}
