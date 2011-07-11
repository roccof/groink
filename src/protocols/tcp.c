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

static int l_tcp_src_port(lua_State *L)
{
  header_t *header = NULL;
  tcp_t *tcp = NULL;
  
  header = check_header(L, 1);
  tcp = (tcp_t *)header->data;

  lua_pushnumber(L, ntohs(tcp->src_port));

  return 1;
}

static int l_tcp_dst_port(lua_State *L)
{
  header_t *header = NULL;
  tcp_t *tcp = NULL;
  
  header = check_header(L, 1);
  tcp = (tcp_t *)header->data;

  lua_pushnumber(L, ntohs(tcp->dest_port));

  return 1;
}

static int l_tcp_seq(lua_State *L)
{
  header_t *header = NULL;
  tcp_t *tcp = NULL;
  
  header = check_header(L, 1);
  tcp = (tcp_t *)header->data;

  lua_pushnumber(L, ntohl(tcp->seq));

  return 1;
}

static int l_tcp_ack(lua_State *L)
{
  header_t *header = NULL;
  tcp_t *tcp = NULL;
  
  header = check_header(L, 1);
  tcp = (tcp_t *)header->data;

  lua_pushnumber(L, ntohl(tcp->ack));

  return 1;
}

static int l_tcp_dataoffset(lua_State *L)
{
  header_t *header = NULL;
  tcp_t *tcp = NULL;
  
  header = check_header(L, 1);
  tcp = (tcp_t *)header->data;

  lua_pushnumber(L, tcp->offset);

  return 1;
}

static int l_tcp_flags(lua_State *L)
{
  header_t *header = NULL;
  tcp_t *tcp = NULL;
  
  header = check_header(L, 1);
  tcp = (tcp_t *)header->data;

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

  return 1;
}

static int l_tcp_cksum(lua_State *L)
{
  header_t *header = NULL;
  tcp_t *tcp = NULL;
  
  header = check_header(L, 1);
  tcp = (tcp_t *)header->data;

  lua_pushnumber(L, ntohs(tcp->checksum));

  return 1;
}

static int l_tcp_window(lua_State *L)
{
  header_t *header = NULL;
  tcp_t *tcp = NULL;
  
  header = check_header(L, 1);
  tcp = (tcp_t *)header->data;

  lua_pushnumber(L, ntohs(tcp->win));

  return 1;
}

static int l_tcp_urg_pointer(lua_State *L)
{
  header_t *header = NULL;
  tcp_t *tcp = NULL;
  
  header = check_header(L, 1);
  tcp = (tcp_t *)header->data;

  lua_pushnumber(L, ntohs(tcp->urgp));

  return 1;
}

static const struct luaL_reg tcp_methods[] = {
  {"src_port", l_tcp_src_port},
  {"dst_port", l_tcp_dst_port},
  {"seq", l_tcp_seq},
  {"ack", l_tcp_ack},
  {"data_offset", l_tcp_dataoffset},
  {"flags", l_tcp_flags},
  {"window", l_tcp_window},
  {"cksum", l_tcp_cksum},
  {"urg_pointer", l_tcp_urg_pointer},
  /* {"options", l_tcp_options} */
  {NULL, NULL}
};

void register_tcp()
{
  proto_t *p = (proto_t *)safe_alloc(sizeof(proto_t));
  p->name = PROTO_NAME_TCP;
  p->longname = "Trasmission Control Protocol";
  p->layer = L4;
  p->decoder = decode_tcp;
  p->methods = (luaL_reg *)tcp_methods;
  
  proto_register_byname(PROTO_NAME_TCP, p);
}
