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

#include "base.h"
#include "decoder.h"
#include "udp.h"
#include "packet.h"
#include "debug.h"
#include "protos.h"
#include "protos_name.h"
#include "selib.h"

static int decode_udp(packet_t *p, const _uint8 *bytes, size_t len)
{
  int status = DECODE_OK;
  udp_t *udp = NULL;

  if (UDP_HDR_LEN > len) {
    decoder_add_error(p, "invalid UDP header length");
    return call_decoder(PROTO_NAME_RAW, p, bytes, len);
  }

  udp = (udp_t *)bytes;

  packet_append_header(p, PROTO_NAME_UDP, (void *)udp, UDP_HDR_LEN);

  p->src_port = udp->src_port;
  p->dst_port = udp->dest_port;

  if ((len - UDP_HDR_LEN) > 0) {
    status += call_decoder_byport(ntohs(udp->src_port), p, (bytes + UDP_HDR_LEN), (len - UDP_HDR_LEN));
    
    if (status == DECODER_NOT_FOUND)
      status += call_decoder_byport(ntohs(udp->dest_port), p, (bytes + UDP_HDR_LEN), (len - UDP_HDR_LEN));
    
    if (status == DECODER_NOT_FOUND)
      status = call_decoder(PROTO_NAME_RAW, p, (bytes + UDP_HDR_LEN), (len - UDP_HDR_LEN));
  }
  
  return status;
}

static int l_udp_dst_port(lua_State *L)
{
  header_t *header = NULL;
  udp_t *udp = NULL;
  
  header = check_header(L, 1);
  udp = (udp_t *)header->data;

  lua_pushnumber(L, ntohs(udp->dest_port));

  return 1;
}

static int l_udp_src_port(lua_State *L)
{
  header_t *header = NULL;
  udp_t *udp = NULL;
  
  header = check_header(L, 1);
  udp = (udp_t *)header->data;

  lua_pushnumber(L, ntohs(udp->src_port));

  return 1;
}

static int l_udp_payload_len(lua_State *L)
{
  header_t *header = NULL;
  udp_t *udp = NULL;
  
  header = check_header(L, 1);
  udp = (udp_t *)header->data;

  lua_pushnumber(L, ntohs(udp->len));

  return 1;
}

static int l_udp_cksum(lua_State *L)
{
  header_t *header = NULL;
  udp_t *udp = NULL;
  
  header = check_header(L, 1);
  udp = (udp_t *)header->data;

  lua_pushnumber(L, ntohs(udp->checksum));

  return 1;
}

static const struct luaL_reg udp_methods[] = {
  {"dst_port", l_udp_dst_port},
  {"src_port", l_udp_src_port},
  {"cksum", l_udp_cksum},
  {"payload_len", l_udp_payload_len},
  {NULL, NULL}
};

void register_udp()
{
  proto_t *p = (proto_t *)safe_alloc(sizeof(proto_t));
  p->name = PROTO_NAME_UDP;
  p->longname = "User Datagram  Protocol";
  p->layer = L4;
  p->decoder = decode_udp;
  p->methods = (luaL_reg *)udp_methods;
  
  proto_register_byname(PROTO_NAME_UDP, p);
}
