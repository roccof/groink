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
#include <lualib.h>

#include "protocols/ethernet.h"
#include "protocols/arp.h"
#include "protocols/pppoe.h"
#include "protocols/ipv4.h"
#include "protocols/icmp.h"
#include "protos_name.h"
#include "selib.h"

struct _grk_consts {
  char *name;
  const se_constant_t *values;
};

static const se_constant_t protos_const[] = {
  {"ETHER", { .str = PROTO_NAME_ETHER }, SE_TSTRING},
  {"ARP", { .str = PROTO_NAME_ARP }, SE_TSTRING},
  {"PPPOE", { .str = PROTO_NAME_PPPOE }, SE_TSTRING},
  {"RAW", { .str = PROTO_NAME_RAW }, SE_TSTRING},
  {"IPV4", { .str = PROTO_NAME_IPV4 }, SE_TSTRING},
  {"TCP", { .str = PROTO_NAME_TCP }, SE_TSTRING},
  {"UDP", { .str = PROTO_NAME_UDP }, SE_TSTRING},
  {"ICMP", { .str = PROTO_NAME_ICMP }, SE_TSTRING},
  {"IPV6", { .str = PROTO_NAME_IPV6 }, SE_TSTRING},
  {NULL, { .num = 0 }, SE_TNUMBER}
};

static const se_constant_t icmp_const[] = {
  {"HDR_LEN", { .num = ICMP_HDR_LEN }, SE_TNUMBER},
  {"TYPE_ECHO_REPLY", { .num = ICMP_TYPE_ECHOREPLY }, SE_TNUMBER},
  {"TYPE_DEST_UNREACH", { .num = ICMP_TYPE_DEST_UNREACH }, SE_TNUMBER},
  {"TYPE_SOURCE_QUENCH", { .num = ICMP_TYPE_SOURCE_QUENCH }, SE_TNUMBER},
  {"TYPE_REDIRECT", { .num = ICMP_TYPE_REDIRECT }, SE_TNUMBER},
  {"TYPE_ECHO", { .num = ICMP_TYPE_ECHO }, SE_TNUMBER},
  {"TYPE_ROUTER_ADV", { .num = ICMP_TYPE_ROUTER_ADV }, SE_TNUMBER},
  {"TYPE_ROUTER_SOL", { .num = ICMP_TYPE_ROUTER_SOL }, SE_TNUMBER},
  {"TYPE_TIME_EXCEEDED", { .num = ICMP_TYPE_TIME_EXCEEDED }, SE_TNUMBER},
  {"TYPE_PARAM_PROB", { .num = ICMP_TYPE_PARAM_PROB }, SE_TNUMBER},
  {"TYPE_TIMESTAMP", { .num = ICMP_TYPE_TIMESTAMP }, SE_TNUMBER},
  {"TYPE_TIMESTAMPREPLY", { .num = ICMP_TYPE_TIMESTAMPREPLY }, SE_TNUMBER},
  {"TYPE_INFO_REQUEST", { .num = ICMP_TYPE_INFO_REQUEST }, SE_TNUMBER},
  {"TYPE_INFO_REPLY", { .num = ICMP_TYPE_INFO_REPLY }, SE_TNUMBER},
  {"TYPE_ADDRESS", { .num = ICMP_TYPE_ADDRESS }, SE_TNUMBER},
  {"TYPE_ADDRESSREPLY", { .num = ICMP_TYPE_ADDRESSREPLY }, SE_TNUMBER},
  {"TYPE_TRACEROUTE", { .num = ICMP_TYPE_TRACEROUTE }, SE_TNUMBER},
  {"CODE_UNREACH_NET", { .num = ICMP_UN_NET_UNREACH }, SE_TNUMBER},
  {"CODE_UNREACH_HOST", { .num = ICMP_UN_HOST_UNREACH }, SE_TNUMBER},
  {"CODE_UNREACH_PROTO", { .num = ICMP_UN_PROT_UNREACH }, SE_TNUMBER},
  {"CODE_UNREACH_PORT", { .num = ICMP_UN_PORT_UNREACH }, SE_TNUMBER},
  {"CODE_UNREACH_FRAG_NEEDED", { .num = ICMP_UN_FRAG_NEEDED }, SE_TNUMBER},
  {"CODE_UNREACH_SR_FAILED", { .num = ICMP_UN_SR_FAILED }, SE_TNUMBER},
  {"CODE_UNREACH_NET_UNKNOWN", { .num = ICMP_UN_NET_UNKNOWN }, SE_TNUMBER},
  {"CODE_UNREACH_HOST_UNKNOWN", { .num = ICMP_UN_HOST_UNKNOWN }, SE_TNUMBER},
  {"CODE_UNREACH_HOST_ISOLATED", { .num = ICMP_UN_HOST_ISOLATED }, SE_TNUMBER},
  {"CODE_UNREACH_NET_ANO", { .num = ICMP_UN_NET_ANO }, SE_TNUMBER},
  {"CODE_UNREACH_HOST_ANO", { .num = ICMP_UN_HOST_ANO }, SE_TNUMBER},
  {"CODE_UNREACH_NET_UNR_TOS", { .num = ICMP_UN_NET_UNR_TOS }, SE_TNUMBER},
  {"CODE_UNREACH_HOST_UNR_TOS", { .num = ICMP_UN_HOST_UNR_TOS }, SE_TNUMBER},
  {"CODE_UNREACH_PKT_FILTERED", { .num = ICMP_UN_PKT_FILTERED }, SE_TNUMBER},
  {"CODE_UNREACH_PREC_VIOLATION", { .num = ICMP_UN_PREC_VIOLATION }, SE_TNUMBER},
  {"CODE_UNREACH_PREC_CUTOFF", { .num = ICMP_UN_PREC_CUTOFF }, SE_TNUMBER},
  {"CODE_REDIR_NET", { .num = ICMP_REDIR_NET }, SE_TNUMBER},
  {"CODE_REDIR_HOST", { .num = ICMP_REDIR_HOST }, SE_TNUMBER},
  {"CODE_REDIR_NET_TOS", { .num = ICMP_REDIR_NETTOS }, SE_TNUMBER},
  {"CODE_REDIR_HOST_TOS", { .num = ICMP_REDIR_HOSTTOS }, SE_TNUMBER},
  {"CODE_TEXC_TTL", { .num = ICMP_TEXC_TTL }, SE_TNUMBER},
  {"CODE_TEXC_FRAGTIME", { .num = ICMP_TEXC_FRAGTIME }, SE_TNUMBER},
  {NULL, { .num = 0 }, SE_TNUMBER}
};

static const se_constant_t ip_const[] = {
  {"MAX_PACKET_SIZE", { .num = IPV4_MAXPACKET }, SE_TNUMBER},
  {"MAX_PACKET_MAX_TTL", { .num = IPV4_MAXTTL }, SE_TNUMBER},
  {"MAX_PACKET_DEFAULT_TTL", { .num = IPV4_DEFTTL }, SE_TNUMBER},
  {NULL, { .num = 0 }, SE_TNUMBER}
};

static const se_constant_t arp_const[] = {
  {"OP_REQUEST", { .num = ARP_OP_REQUEST }, SE_TNUMBER},
  {"OP_REPLY", { .num = ARP_OP_REPLY }, SE_TNUMBER},
  {"OP_RREQUEST", { .num = ARP_OP_RREQUEST }, SE_TNUMBER},
  {"OP_RREPLY", { .num = ARP_OP_RREPLY }, SE_TNUMBER},
  {"OP_InREQUEST", { .num = ARP_OP_InREQUEST }, SE_TNUMBER},
  {"OP_InREPLY", { .num = ARP_OP_InREPLY }, SE_TNUMBER},
  {"OP_NAK", { .num = ARP_OP_NAK }, SE_TNUMBER},
  {NULL, { .num = 0 }, SE_TNUMBER}
};

static const se_constant_t pppoe_const[] = {
  {"HDR_LEN", { .num = PPPOE_HDR_LEN }, SE_TNUMBER},
  {"CODE_SESSION", { .num = PPPOE_CODE_SESSION }, SE_TNUMBER},
  {"CODE_DISCOVER_PADI", { .num = PPPOE_CODE_DISCOVER_PADI }, SE_TNUMBER},
  {"CODE_DISCOVER_PADO", { .num = PPPOE_CODE_DISCOVER_PADO }, SE_TNUMBER},
  {"CODE_DISCOVER_PADR", { .num = PPPOE_CODE_DISCOVER_PADR }, SE_TNUMBER},
  {"CODE_DISCOVER_PADS", { .num = PPPOE_CODE_DISCOVER_PADS }, SE_TNUMBER},
  {"CODE_DISCOVER_PADT", { .num = PPPOE_CODE_DISCOVER_PADT }, SE_TNUMBER},
  {"TAG_TYPE_EOL", { .num = PPPOE_TAG_TYPE_EOL }, SE_TNUMBER},
  {"TAG_TYPE_SERV_NAME", { .num = PPPOE_TAG_TYPE_SERV_NAME }, SE_TNUMBER},
  {"TAG_TYPE_AC_NAME", { .num = PPPOE_TAG_TYPE_AC_NAME }, SE_TNUMBER},
  {"TAG_TYPE_HOST_UNIQ", { .num = PPPOE_TAG_TYPE_HOST_UNIQ }, SE_TNUMBER},
  {"TAG_TYPE_AC_COOKIE", { .num = PPPOE_TAG_TYPE_AC_COOKIE }, SE_TNUMBER},
  {"TAG_TYPE_VENDOR_SPEC", { .num = PPPOE_TAG_TYPE_VENDOR_SPEC }, SE_TNUMBER},
  {"TAG_TYPE_REL_SESS_ID", { .num = PPPOE_TAG_TYPE_REL_SESS_ID }, SE_TNUMBER},
  {"TAG_TYPE_SERV_NAME_ERR", { .num = PPPOE_TAG_TYPE_SERV_NAME_ERR }, SE_TNUMBER},
  {"TAG_TYPE_AC_SYS_ERR", { .num = PPPOE_TAG_TYPE_AC_SYS_ERR }, SE_TNUMBER},
  {"TAG_TYPE_GEN_ERR", { .num = PPPOE_TAG_TYPE_GEN_ERR }, SE_TNUMBER},
  {NULL, { .num = 0 }, SE_TNUMBER}
};

static const struct _grk_consts consts[] = {
  {"Proto", protos_const},
  {"ARP", arp_const},
  {"PPPoE", pppoe_const},
  {"IPv4", ip_const},
  {"ICMP", icmp_const},
  {NULL, NULL}
};

void se_open_constants(lua_State *L)
{
  int i = 0, j = 0;

  for (i=0; consts[i].name!=NULL; i++) {
    se_constant_t *c = (se_constant_t *)consts[i].values;

    lua_newtable(L);

    for (j=0; c[j].name!=NULL; j++) {
      lua_pushstring(L, c[j].name);

      if (c[j].type == SE_TNUMBER)
	lua_pushnumber(L, c[j].value.num);
      else if (c[j].type == SE_TSTRING)
	lua_pushstring(L, c[j].value.str);
      else
	lua_pushboolean(L, c[j].value.num);

      lua_settable(L, -3);
    }
    
    /* Make table read-only */
    se_setro(L);

    lua_setglobal(L, consts[i].name);
  }
}
