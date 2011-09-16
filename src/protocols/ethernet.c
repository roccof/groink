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
#include <string.h>
#include <lua.h>

#include "ethernet.h"
#include "debug.h"
#include "netutil.h"
#include "packet.h"
#include "base.h"
#include "protos.h"
#include "protos_name.h"
#include "selib.h"

/* Builder */
ether_t *build_ethernet(char *src, char *dst, _uint16 type)
{
  ether_t *ether = NULL;
  _uint8 *bytes;

  ether = (ether_t *)safe_alloc(sizeof(ether_t));

  bytes = ether_addr_aton(dst);
  memcpy(ether->dest_addr, bytes, ETHER_ADDR_LEN);
  free(bytes);

  bytes = ether_addr_aton(src);
  memcpy(ether->src_addr, bytes, ETHER_ADDR_LEN);
  free(bytes);

  ether->type = htons(type);

  return ether;
}

/* Decoder */
static int decode_ether(packet_t *p, const _uint8 *bytes, size_t len)
{
  ether_t *eth = NULL;

  if (ETHER_HDR_LEN > len) {
    decoder_add_error(p, "invalid ETHERNET header length");
    /* packet_set_tostring(p, "ETHER| invalid length %d", len); */
    return call_decoder(PROTO_NAME_RAW, p, bytes, len);
  }

  eth = (ether_t *)bytes;

  packet_append_header(p, PROTO_NAME_ETHER, (void *)eth, ETHER_HDR_LEN);

  p->hw_srcaddr = ether_addr_ntoa(eth->src_addr);
  p->hw_dstaddr = ether_addr_ntoa(eth->dest_addr);

  switch (ntohs(eth->type)) {
    
  case ETHER_TYPE_IP:
    return call_decoder(PROTO_NAME_IPV4, p, (bytes + ETHER_HDR_LEN), 
			(len - ETHER_HDR_LEN));
    
  case ETHER_TYPE_IPV6:
    return call_decoder(PROTO_NAME_IPV6, p, (bytes + ETHER_HDR_LEN), 
			(len - ETHER_HDR_LEN));
    
  case ETHER_TYPE_ARP:
  case ETHER_TYPE_REVARP:
    return call_decoder(PROTO_NAME_ARP, p, (bytes + ETHER_HDR_LEN), 
			(len - ETHER_HDR_LEN));
    
  case ETHER_TYPE_PPPOED:
  case ETHER_TYPE_PPPOES:
    return call_decoder(PROTO_NAME_PPPOE, p, (bytes + ETHER_HDR_LEN), 
			(len - ETHER_HDR_LEN));
    
  default:
    decoder_add_error(p, "unknown ether type protocol");
    /* packet_set_tostring(p, "ETHER %s (%s) > %s (%s) type 0x%04x (unknown)", p->hw_srcaddr,  */
    /* 			(src_oui != NULL)? src_oui : "unknown", p->hw_dstaddr,  */
    /* 			(dst_oui != NULL)? dst_oui : "unknown", ntohs(eth->type)); */
    return call_decoder(PROTO_NAME_RAW, p, (bytes + ETHER_HDR_LEN), 
			(len - ETHER_HDR_LEN));
  }
}

static int l_dissect_ether(lua_State *L)
{
  header_t *h = NULL;
  ether_t *e = NULL;
  char *addr = NULL;
  
  h = check_header(L, 1);
  e = (ether_t *)h->data;

  lua_newtable(L);

  lua_pushstring(L, "src_addr");
  addr = ether_addr_ntoa(e->src_addr);
  lua_pushstring(L, addr);
  free(addr);
  lua_settable(L, -3);

  lua_pushstring(L, "dst_addr");
  addr = ether_addr_ntoa(e->dest_addr);
  lua_pushstring(L, addr);
  free(addr);
  lua_settable(L, -3);

  lua_pushstring(L, "type");
  lua_pushnumber(L, ntohs(e->type));
  lua_settable(L, -3);

  se_setro(L);

  return 1;
}

void register_ether()
{
  proto_t *p = (proto_t *)safe_alloc(sizeof(proto_t));
  p->name = PROTO_NAME_ETHER;
  p->longname = "Ethernet";
  p->layer = L2;
  p->decoder = decode_ether;
  p->dissect = l_dissect_ether;
  
  proto_register_byname(PROTO_NAME_ETHER, p);
}
