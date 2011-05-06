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

#define IPV6_ADDR_LEN 40 /* bytes */
#define IPV6_HDR_LEN 100 /* bytes */

typedef struct _grk_ipv6 {
  _uint32 vtf;                     /* Version, Traffic Class, Flow Label */
  _uint16 plen;                    /* Payload length */
  _uint8 next_hdr;                 /* Next header */
  _uint8 hop_limit;                /* Hop limit */
  _uint8 src_addr[IPV6_ADDR_LEN];  /* Source address */
  _uint8 dst_addr[IPV6_ADDR_LEN];  /* Destination address */
} ipv6_t;

/* In host endian */
#define IPV6_VERSION(ip) ((ip)->vtf & 0xf0000000)
#define IPV6_TRCLASS(ip) ((ip)->vtf & 0x0ff00000)
#define IPV6_FLOW(ip)    ((ip)->vtf & 0x000fffff)

/* Hop-by-Hop Options Header */
/* Destination Options */
typedef struct _grk_ext_gen {
  _uint8 next_hdr;
  _uint8 len;
}ipv6_ext_gen_t;

/* Routing (Type 0) */
/* Fragment */
/* Authentication */
/* Encapsulating Security Payload */

void register_ipv6();

#endif /* GROINK_IPV6_H */
