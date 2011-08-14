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

#include "tcp.h"
#include "base.h"
#include "packet.h"
#include "decoder.h"
#include "debug.h"
#include "protos.h"
#include "protos_name.h"
#include "selib.h"

static int decode_tcp(packet_t *p, const _uint8 *bytes, size_t len)
{
  int status = DECODE_OK;
  unsigned int totlen = 0;
  tcp_t *tcp = NULL;

  if (sizeof(tcp_t) > len)
    goto err;

  tcp = (tcp_t *)bytes;
  totlen = TCP_HDR_LEN(tcp);

  if (totlen > len)
    goto err;

  packet_append_header(p, PROTO_NAME_TCP, (void *)tcp, totlen);

  p->src_port = tcp->src_port;
  p->dst_port = tcp->dest_port;

  /* If there is more data */
  if ((len - totlen) > 0) {
    status += call_decoder_byport(ntohs(tcp->src_port), p, (bytes + totlen), 
				  (len - totlen));
    
    if (status == DECODER_NOT_FOUND)
      status += call_decoder_byport(ntohs(tcp->dest_port), p, (bytes + totlen), 
				    (len - totlen));
    
    if (status == DECODER_NOT_FOUND)
      status += call_decoder(PROTO_NAME_RAW, p, (bytes + totlen), (len - totlen));
  }
  
  return status;

 err:
  decoder_add_error(p, "invalid TCP header length");
  return call_decoder(PROTO_NAME_RAW, p, bytes, len);
}

static int l_dissect_tcp(lua_State *L)
{
  header_t *header = NULL;
  tcp_t *tcp = NULL;
  
  header = check_header(L, 1);
  tcp = (tcp_t *)header->data;

  lua_newtable(L);

  lua_pushstring(L, "src_port");
  lua_pushnumber(L, ntohs(tcp->src_port));
  lua_settable(L, -3);

  lua_pushstring(L, "dst_port");
  lua_pushnumber(L, ntohs(tcp->dest_port));
  lua_settable(L, -3);

  lua_pushstring(L, "seq");
  lua_pushnumber(L, ntohl(tcp->seq));
  lua_settable(L, -3);

  lua_pushstring(L, "ack");
  lua_pushnumber(L, ntohl(tcp->ack));
  lua_settable(L, -3);

  lua_pushstring(L, "offset");
  lua_pushnumber(L, tcp->offset);
  lua_settable(L, -3);

  lua_pushstring(L, "flags");

  lua_newtable(L);

  lua_pushstring(L, "fin");
  lua_pushboolean(L, (tcp->flags & TCP_FIN) == TCP_FIN);
  lua_settable(L, -3);

  lua_pushstring(L, "syn");
  lua_pushboolean(L, (tcp->flags & TCP_SYN) == TCP_SYN);
  lua_settable(L, -3);

  lua_pushstring(L, "rst");
  lua_pushboolean(L, (tcp->flags & TCP_RST) == TCP_RST);
  lua_settable(L, -3);

  lua_pushstring(L, "push");
  lua_pushboolean(L, (tcp->flags & TCP_PUSH) == TCP_PUSH);
  lua_settable(L, -3);

  lua_pushstring(L, "ack");
  lua_pushboolean(L, (tcp->flags & TCP_ACK) == TCP_ACK);
  lua_settable(L, -3);

  lua_pushstring(L, "urg");
  lua_pushboolean(L, (tcp->flags & TCP_URG) == TCP_URG);
  lua_settable(L, -3);

  se_setro(L);

  lua_settable(L, -3);

  lua_pushstring(L, "cksum");
  lua_pushnumber(L, ntohs(tcp->checksum));
  lua_settable(L, -3);

  lua_pushstring(L, "win");
  lua_pushnumber(L, ntohs(tcp->win));
  lua_settable(L, -3);

  lua_pushstring(L, "urg_pointer");
  lua_pushnumber(L, ntohs(tcp->urgp));
  lua_settable(L, -3);

  se_setro(L);

  return 1;
}

void register_tcp()
{
  proto_t *p = (proto_t *)safe_alloc(sizeof(proto_t));
  p->name = PROTO_NAME_TCP;
  p->longname = "Trasmission Control Protocol";
  p->layer = L4;
  p->decoder = decode_tcp;
  p->dissect = l_dissect_tcp;
  
  proto_register_byname(PROTO_NAME_TCP, p);
}
