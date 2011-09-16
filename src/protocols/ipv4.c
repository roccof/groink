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

  if (len < sizeof(ipv4_t)) {
    decoder_add_error(p, "invalid IPv4 header length");
    return call_decoder(PROTO_NAME_RAW, p, bytes, len);
  }

  ip = (ipv4_t *)bytes;

  /* Control if IHL is valid, min 20 bytes */
  if (IPV4_HDR_LEN(ip) < sizeof(ipv4_t)) {
    decoder_add_error(p, "invalid IPv4 header length");
    return call_decoder(PROTO_NAME_RAW, p, bytes, len);
  }

  packet_append_header(p, PROTO_NAME_IPV4, (void *)ip, IPV4_HDR_LEN(ip));
  
  p->net_srcaddr = ip_addr_ntoa(ip->src_addr);
  p->net_dstaddr = ip_addr_ntoa(ip->dest_addr);
  
  /* Control VERSION */
  if (IPV4_VERS(ip) != 4)
    debug("packet decoding: bad IPv4 VERSION (%d)", IPV4_VERS(ip));

  switch (ip->proto) {

  case IPV4_PROTO_TCP:
    return call_decoder(PROTO_NAME_TCP, p, (bytes + IPV4_HDR_LEN(ip)),
			(len - IPV4_HDR_LEN(ip)));
    
  case IPV4_PROTO_UDP:
    return call_decoder(PROTO_NAME_UDP, p, (bytes + IPV4_HDR_LEN(ip)),
			(len - IPV4_HDR_LEN(ip)));
    
  case IPV4_PROTO_ICMP:
    return call_decoder(PROTO_NAME_ICMP, p, (bytes + IPV4_HDR_LEN(ip)),
			(len - IPV4_HDR_LEN(ip)));
    
  default: /* Unknown layer 4 protocol */
    decoder_add_error(p, "unknown layer 4 protocol");
    return call_decoder(PROTO_NAME_RAW, p, (bytes + IPV4_HDR_LEN(ip)), 
			(len - IPV4_HDR_LEN(ip)));
  }
}

static int l_dissect_ipv4(lua_State *L)
{
  header_t *header = NULL;
  ipv4_t *ip = NULL;
  char *addr = NULL;
  
  header = check_header(L, 1);
  ip = (ipv4_t *)header->data;

  lua_newtable(L);
  
  lua_pushstring(L, "ihl");
  lua_pushnumber(L, IPV4_IHL(ip));
  lua_settable(L, -3);

  lua_pushstring(L, "version");
  lua_pushnumber(L, IPV4_VERS(ip));
  lua_settable(L, -3);
  
  lua_pushstring(L, "tos");
  lua_pushnumber(L, ip->tos);
  lua_settable(L, -3);

  lua_pushstring(L, "totlen");
  lua_pushnumber(L, ntohs(ip->len));
  lua_settable(L, -3);

  lua_pushstring(L, "id");
  lua_pushnumber(L, ntohs(ip->id));
  lua_settable(L, -3);

  lua_pushstring(L, "frag_offset");
  lua_pushnumber(L, ((ntohs(ip->frag_offset) & IPV4_FRAG) == IPV4_FRAG));
  lua_settable(L, -3);

  lua_pushstring(L, "df");
  lua_pushboolean(L, ((ntohs(ip->frag_offset) & IPV4_DF) == IPV4_DF));
  lua_settable(L, -3);

  lua_pushstring(L, "mf");
  lua_pushboolean(L, ((ntohs(ip->frag_offset) & IPV4_MF) == IPV4_MF));
  lua_settable(L, -3);

  lua_pushstring(L, "rf");
  lua_pushboolean(L, ((ntohs(ip->frag_offset) & IPV4_RF) == IPV4_RF));
  lua_settable(L, -3);

  lua_pushstring(L, "ttl");
  lua_pushnumber(L, ip->ttl);
  lua_settable(L, -3);

  lua_pushstring(L, "proto");
  lua_pushnumber(L, ip->proto);
  lua_settable(L, -3);

  lua_pushstring(L, "cksum");
  lua_pushnumber(L, ip->checksum);
  lua_settable(L, -3);

  lua_pushstring(L, "src_addr");
  addr = ip_addr_ntoa(ip->src_addr);
  lua_pushstring(L, addr);
  free(addr);
  lua_settable(L, -3);

  lua_pushstring(L, "dst_addr");
  addr = ip_addr_ntoa(ip->dest_addr);
  lua_pushstring(L, addr);
  free(addr);
  lua_settable(L, -3);

  se_setro(L);

  return 1;
}

void register_ipv4()
{
  proto_t *p = (proto_t *)safe_alloc(sizeof(proto_t));
  p->name = PROTO_NAME_IPV4;
  p->longname = "Internet Protocol version 4";
  p->layer = L3;
  p->decoder = decode_ipv4;
  p->dissect = l_dissect_ipv4;
  
  proto_register_byname(PROTO_NAME_IPV4, p);
}
