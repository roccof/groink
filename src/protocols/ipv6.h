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
#ifndef GROINK_IPV6_H
#define GROINK_IPV6_H

#include <netinet/in.h>
#include <arpa/inet.h>

#include "base.h"

/*
 * RFC 2460 - IPv6 HEADER
 * ======================
 *
 * 0                   1                   2                   3   
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |Version| Traffic Class |           Flow Label                  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Payload Length        |  Next Header  |   Hop Limit   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * +                                                               +
 * |                                                               |
 * +                         Source Address                        +
 * |                                                               |
 * +                                                               +
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * +                                                               +
 * |                                                               |
 * +                      Destination Address                      +
 * |                                                               |
 * +                                                               +
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

#define IPV6_ADDR_LEN 16 /* bytes */
#define IPV6_HDR_LEN 40 /* bytes */

typedef struct _grk_ipv6 {
  _uint32 vtf;                     /* Version, Traffic Class, Flow Label */
  _uint16 plen;                    /* Payload length */
  _uint8 next_hdr;                 /* Next header */
  _uint8 hop_limit;                /* Hop limit */
  _uint8 src_addr[IPV6_ADDR_LEN];  /* Source address */
  _uint8 dst_addr[IPV6_ADDR_LEN];  /* Destination address */
} ipv6_t;

/* In host endian */
#define IPV6_VERSION(ip) ((ntohl((ip)->vtf) & 0xf0000000) >> 28)
#define IPV6_TRCLASS(ip) ((ntohl((ip)->vtf) & 0x0ff00000) >> 20)
#define IPV6_FLOW(ip)    (ntohl((ip)->vtf) & 0x000fffff)

#define IPV6_PROTO_ICMP 58

/* Extension headers */
#define IPV6_EXTH_HBH 0
#define IPV6_EXTH_DST_OPT 60
#define IPV6_EXTH_ROUTING 43
#define IPV6_EXTH_FRAG 44
#define IPV6_EXTH_AH 51
#define IPV6_EXTH_ESP 50
#define IPV6_NO_EXT_HDR 59

/* Hop-by-Hop Options & Destination Options */
typedef struct _grk_ipv6_ext_opt {
  _uint8 next_hdr;        /* Next header */
  _uint8 len;             /* Header extension header len */
} ipv6_ext_opt_t;

/* Routing (Type 0) */
typedef struct _grk_ipv6_ext_routing {
  _uint8 next_hdr;
  _uint8 len;
  _uint8 routing_type;
  _uint8 seg_left;
  _uint32 reserved;
} ipv6_ext_routing_t;

/* Fragment */
typedef struct _grk_ipv6_ext_frag {
  _uint8 next_hdr;
  _uint8 reserved;
  _uint16 frags;
  _uint16 id;
} ipv6_ext_frag_t;

#define IPV6_EXT_FRAG_FRAGOFF(ip)  ((ip)->frags & 0xfff8)
#define IPV6_EXT_FRAG_MOREFRAG(ip) ((ip)->frags & 0x0001)

/* Authentication */
typedef struct _grk_ipv6_ext_auth {
  _uint8 next_hdr;
  _uint8 plen;
  _uint16 reserved;
  _uint32 spi;
  _uint32 seq;
} ipv6_ext_auth_t;

/* Encapsulating Security Payload */
typedef struct _grk_ipv6_ext_esp {
  
} ipv6_ext_esp_t;

void register_ipv6();

#endif /* GROINK_IPV6_H */
