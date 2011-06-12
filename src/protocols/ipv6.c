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
#include "ipv6.h"
#include "ipv4.h"
#include "protos.h"
#include "protos_name.h"
#include "netutil.h"
#include "selib.h"

static int decode_ipv6(packet_t *p, const _uint8 *bytes, size_t len)
{
  ipv6_t *ip = NULL;
  header_t *h = NULL;
  _uint8 nexth;
  _uint totlen = 0;
  ipv6_ext_opt_t *opt = NULL;
  ipv6_ext_routing_t *r = NULL;
  ipv6_ext_frag_t *f = NULL;

  if (len < IPV6_HDR_LEN) {
    debug("IPv6 decoder: too short");
    call_decoder(PROTO_NAME_RAW, p, bytes, len);
  }

  ip = (ipv6_t *)bytes;
  totlen += IPV6_HDR_LEN;

  h = packet_append_header(p, PROTO_NAME_IPV6, (void *)ip, IPV6_HDR_LEN);
  
  p->net_srcaddr = ipv6_addr_ntoa(ip->src_addr);
  p->net_dstaddr = ipv6_addr_ntoa(ip->dst_addr);

  nexth = ip->next_hdr;

  while (1) {
    switch (nexth) {

    case IPV6_EXTH_HBH:
    case IPV6_EXTH_DST_OPT:
      opt = (ipv6_ext_opt_t *)(bytes + totlen);
      totlen += sizeof(ipv6_ext_opt_t) + opt->len;
      nexth = opt->next_hdr;
      break;

    case IPV6_EXTH_ROUTING:
      r = (ipv6_ext_routing_t *)(bytes + totlen);
      totlen += sizeof(ipv6_ext_routing_t) + r->len;
      nexth = r->next_hdr;
      break;

    case IPV6_EXTH_FRAG:
      f = (ipv6_ext_frag_t *)(bytes + totlen);
      totlen += sizeof(ipv6_ext_frag_t);
      nexth = f->next_hdr;
      break;

    case IPV6_EXTH_AH:
      debug("IPv6 decoder: AH extension header not implemented");
      return totlen;

    case IPV6_EXTH_ESP:
      debug("IPv6 decoder: ESP extension header not implemented");
      return totlen;

    case IPV4_PROTO_TCP:
      totlen += call_decoder(PROTO_NAME_TCP, p, (bytes + totlen), (len - totlen));
      return totlen;
      
    case IPV4_PROTO_UDP:
      totlen += call_decoder(PROTO_NAME_UDP, p, (bytes + totlen), (len - totlen));
      return totlen;

    case IPV4_PROTO_ICMP:
      totlen += call_decoder(PROTO_NAME_ICMP, p, (bytes + totlen), (len - totlen));
      return totlen;

    case IPV6_PROTO_ICMP:
      return totlen;

    case IPV6_NO_EXT_HDR: /* No extension header */
      return totlen;

    default:
      /* Unknown layer 4 protocol or extension header */
      totlen += call_decoder(PROTO_NAME_RAW, p, (bytes + totlen), (len - totlen));
      return totlen;
    }
    break;
  }

  return DECODE_OK;
}

static int l_ipv6_version(lua_State *L)
{
  header_t *header = NULL;
  ipv6_t *ip = NULL;
  
  header = check_header(L, 1);
  ip = (ipv6_t *)header->data;

  lua_pushnumber(L, IPV6_TRCLASS(ip));
  return 1;
}

static int l_ipv6_tclass(lua_State *L)
{
  header_t *header = NULL;
  ipv6_t *ip = NULL;
  
  header = check_header(L, 1);
  ip = (ipv6_t *)header->data;

  lua_pushnumber(L, IPV6_FLOW(ip));
  return 1;
}

static int l_ipv6_flow(lua_State *L)
{
  header_t *header = NULL;
  ipv6_t *ip = NULL;
  
  header = check_header(L, 1);
  ip = (ipv6_t *)header->data;

  lua_pushnumber(L, IPV6_VERSION(ip));
  return 1;
}

static int l_ipv6_plen(lua_State *L)
{
  header_t *header = NULL;
  ipv6_t *ip = NULL;
  
  header = check_header(L, 1);
  ip = (ipv6_t *)header->data;

  lua_pushnumber(L, ntohs(ip->plen));
  return 1;
}

static int l_ipv6_nexthdr(lua_State *L)
{
  header_t *header = NULL;
  ipv6_t *ip = NULL;
  
  header = check_header(L, 1);
  ip = (ipv6_t *)header->data;

  lua_pushnumber(L, ip->next_hdr);
  return 1;
}

static int l_ipv6_hoplimit(lua_State *L)
{
  header_t *header = NULL;
  ipv6_t *ip = NULL;
  
  header = check_header(L, 1);
  ip = (ipv6_t *)header->data;

  lua_pushnumber(L, ip->hop_limit);
  return 1;
}

static int l_ipv6_src_addr(lua_State *L)
{
  header_t *header = NULL;
  ipv6_t *ip = NULL;
  char *addr = NULL;
  
  header = check_header(L, 1);
  ip = (ipv6_t *)header->data;

  addr = ipv6_addr_ntoa(ip->src_addr);
  lua_pushstring(L, addr);
  free(addr);
  return 1;
}

static int l_ipv6_dst_addr(lua_State *L)
{
  header_t *header = NULL;
  ipv6_t *ip = NULL;
  char *addr = NULL;
  
  header = check_header(L, 1);
  ip = (ipv6_t *)header->data;

  addr = ipv6_addr_ntoa(ip->dst_addr);
  lua_pushstring(L, addr);
  free(addr);
  return 1;
}

static const struct luaL_reg ip6_methods[] = {
  {"version", l_ipv6_version},
  {"traffic_class", l_ipv6_tclass},
  {"flow_label", l_ipv6_flow},
  {"payload_length", l_ipv6_plen},
  {"next_hdr", l_ipv6_nexthdr},
  {"hop_limit", l_ipv6_hoplimit},
  {"src_addr", l_ipv6_src_addr},
  {"dst_addr", l_ipv6_dst_addr},
  {NULL, NULL}
};

void register_ipv6()
{
  proto_t *p = (proto_t *)safe_alloc(sizeof(proto_t));
  p->name = PROTO_NAME_IPV6;
  p->longname = "Internet Protocol version 6";
  p->layer = L3;
  p->decoder = decode_ipv6;
  p->methods = (luaL_reg *)ip6_methods;
  
  proto_register_byname(PROTO_NAME_IPV6, p);
}
