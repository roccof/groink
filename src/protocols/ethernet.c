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

#include "ethernet.h"
#include "debug.h"
#include "netutil.h"
#include "packet.h"
#include "base.h"
#include "protos.h"
#include "protos_name.h"

/* Builder */
ether_t *build_ethernet(char *src, char *dst, _uint16 type)
{
  /* ether_t *ether = NULL; */
  /* _uint8 *bytes; */

  /* ether = (ether_t *)safe_alloc(sizeof(ether_t)); */

  /* bytes = ether_addr_aton(dst); */
  /* memcpy(ether->dest_addr, bytes, ETHER_ADDR_LEN); */
  /* free(bytes); */

  /* bytes = ether_addr_aton(src); */
  /* memcpy(ether->src_addr, bytes, ETHER_ADDR_LEN); */
  /* free(bytes); */

  /* ether->type = htons(type); */

  /* return ether; */
  return NULL;
}

/* Decoder */
static int decode_ether(packet_t *p, const _uint8 *bytes, size_t len)
{
  ether_t *eth = NULL;
  header_t *header = NULL;

  if (ETHER_HDR_LEN > len) {
    debug("malformed ethernet header: invalid length");
    return call_decoder("raw", p, bytes, len);
  }

  eth = (ether_t *)bytes;

  header = packet_add_header(p, PROTO_NAME_ETHER, (void *)eth, ETHER_HDR_LEN);

  p->hw_srcaddr = ether_addr_ntoa(eth->src_addr);
  p->hw_dstaddr = ether_addr_ntoa(eth->dest_addr);

  return DECODE_OK;

  /* switch (ntohs(eth->type)) { */
  /* case ETHER_TYPE_IP: */
  /*   return call_decoder(PROTO_IPV4, p, (bytes + ETHER_HDR_LEN), (len - ETHER_HDR_LEN)); */
    
  /* case ETHER_TYPE_ARP: */
  /* case ETHER_TYPE_REVARP: */
  /*   return call_decoder(PROTO_ARP, p, (bytes + ETHER_HDR_LEN), (len - ETHER_HDR_LEN)); */
    
  /* case ETHER_TYPE_PPPOED: */
  /*   return call_decoder(PROTO_PPPOE, p, (bytes + ETHER_HDR_LEN), (len - ETHER_HDR_LEN)); */
    
  /* case ETHER_TYPE_PPPOES: */
  /*   return call_decoder(PROTO_PPPOE, p, (bytes + ETHER_HDR_LEN), (len - ETHER_HDR_LEN)); */
    
  /* default: */
  /*   /\* Insert error *\/ */
  /*   ADD_ERROR(header, UNKNOWN_ETHER_TYPE); */
  /*   return call_decoder(PROTO_RAW, p, (bytes + ETHER_HDR_LEN), (len - ETHER_HDR_LEN)); */
  /* } */
}

void register_ether()
{
  Protocol *p = (Protocol *)safe_alloc(sizeof(Protocol));
  p->name = PROTO_NAME_ETHER;
  p->longname = "Ethernet";
  p->layer = L2;
  p->decoder = decode_ether;
  
  proto_register_byname(PROTO_NAME_ETHER, p);
}
