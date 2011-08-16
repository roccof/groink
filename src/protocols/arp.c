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
#include "hook.h"
#include "selib.h"
#include "protos.h"
#include "protos_name.h"
#include "packet.h"
#include "arp.h"
#include "netutil.h"

/* Builder */
arp_t *build_arp_ethip(_uint16 opcode, char *sha, char *spa, char *tha, char *tpa)
{
  arp_t *arp = NULL;
  arp_ethip_t *ethip = NULL;
  _uint8 *bytes = NULL;
  _uint32 addr;
  int i;

  arp = (arp_t *)safe_alloc(sizeof(arp_t) + sizeof(arp_ethip_t));
  ethip = (arp_ethip_t *)(arp + 1);

  arp->hrd = htons(ARP_HRD_ETHER);
  arp->pro = htons(ARP_PROTO_IPV4);
  arp->hln = ETHER_ADDR_LEN;
  arp->pln = IPV4_ADDR_LEN;
  arp->opcode = htons(opcode);

  bytes = ether_addr_aton(sha);
  memcpy(ethip->sha, bytes, ETHER_ADDR_LEN);
  free(bytes);

  addr = ip_addr_aton(spa);
  bytes = (_uchar *)&addr;
  for(i=0; i<sizeof(_uint32); i++)
    memcpy((ethip->spa + i), (bytes + i), 1);

  bytes = ether_addr_aton(tha);
  memcpy(ethip->tha, bytes, ETHER_ADDR_LEN);
  free(bytes);

  addr = ip_addr_aton(tpa);
  bytes = (_uchar *)&addr;
  for(i=0; i<sizeof(_uint32); i++)
    memcpy((ethip->tpa + i), (bytes + i), 1);

  return arp;
}

/* Decoder */
static int decode_arp(packet_t *p, const _uint8 *bytes, size_t len)
{
  unsigned int arplen = 0;
  arp_t *arp = NULL;
  hookdata_t *hookdata = NULL;

  if(sizeof(arp_t) > len)
    goto err;

  arp = (arp_t *)bytes;
  arplen = sizeof(arp_t);

  /* If is ethernet arp, the header has more info */
  if(ntohs(arp->hrd) == ARP_HRD_ETHER && ntohs(arp->pro) == ARP_PROTO_IPV4) {
    /* Control length */
    if(arplen + sizeof(arp_ethip_t) > len)
      goto err;
    
    arplen += sizeof(arp_ethip_t);
  }

  packet_append_header(p, PROTO_NAME_ARP, (void *)arp, arplen);

  hookdata = (hookdata_t *)safe_alloc(sizeof(hookdata_t));
  hookdata->type = HOOKDATA_PACKET;
  hookdata->data = p;

  /* Send event */
  hook_event(HOOK_ARP, hookdata);

  free(hookdata);

  return DECODE_OK;

 err:
  decoder_add_error(p, "invalid ARP header length");
  return call_decoder(PROTO_NAME_RAW, p, bytes, len);
}

static int l_dissect_arp(lua_State *L)
{
  header_t *header = NULL;
  arp_t *arp = NULL;
  arp_ethip_t *ether_arp = NULL;
  
  header = check_header(L, 1);
  arp = (arp_t *)header->data;
  
  lua_newtable(L);

  lua_pushstring(L, "hrd");
  lua_pushnumber(L, ntohs(arp->hrd));
  lua_settable(L, -3);

  lua_pushstring(L, "pro");
  lua_pushnumber(L, ntohs(arp->pro));
  lua_settable(L, -3);

  lua_pushstring(L, "hln");
  lua_pushnumber(L, arp->hln);
  lua_settable(L, -3);

  lua_pushstring(L, "pln");
  lua_pushnumber(L, arp->pln);
  lua_settable(L, -3);

  lua_pushstring(L, "opcode");
  lua_pushnumber(L, ntohs(arp->opcode));
  lua_settable(L, -3);

  lua_pushstring(L, "ethip");

  /* 
   * If there are arp ethernet additional info return a
   * table with those info, otherwise return nil
   */
  if (ntohs(arp->hrd) == ARP_HRD_ETHER && ntohs(arp->pro) == ARP_PROTO_IPV4) {
    char *addr = NULL;
    _uint32 *baddr = NULL;
    
    ether_arp = (arp_ethip_t *)(arp + 1);
    
    /* Table with key-value pairs */
    lua_newtable(L);
    
    lua_pushstring(L, "sha");
    addr = ether_addr_ntoa(ether_arp->sha);
    lua_pushstring(L, addr);
    lua_settable(L, -3);
    free(addr);
    
    lua_pushstring(L, "spa");
    baddr = (_uint32 *)ether_arp->spa;
    addr = ip_addr_ntoa(*baddr);
    lua_pushstring(L, addr);
    lua_settable(L, -3);
    free(addr);

    lua_pushstring(L, "tha");
    addr = ether_addr_ntoa(ether_arp->tha);
    lua_pushstring(L, addr);
    lua_settable(L, -3);
    free(addr);

    lua_pushstring(L, "tpa");
    baddr = (_uint32 *)ether_arp->tpa;
    addr = ip_addr_ntoa(*baddr);
    lua_pushstring(L, addr);
    lua_settable(L, -3);
    free(addr);
    
    /* Read-Only table */
    se_setro(L);
  } else {
    lua_pushnil(L);
  }

  lua_settable(L, -3);

  se_setro(L);

  return 1;
}

void register_arp()
{
  proto_t *p = (proto_t *)safe_alloc(sizeof(proto_t));
  p->name = PROTO_NAME_ARP;
  p->longname = "Address Resolution Protocol";
  p->layer = L3;
  p->decoder = decode_arp;
  p->dissect = l_dissect_arp;
  
  proto_register_byname(PROTO_NAME_ARP, p);
}
