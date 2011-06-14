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
#ifndef GROINK_ICMP6_H
#define GROINK_ICMP6_H

/*
 * RFC 2463 - ICMPv6 HEADER
 * ========================
 *
 *   0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |     Code      |          Checksum             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * .                                                               .
 * .             Message body and data (variable)                  .
 * .                                                               .
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

typedef struct _grk_icmp6 {
  _uint8 type;
  _uint8 code;
  _uint16 cksum;
} icmp6_t;

#define ICMP_HDR_LEN sizeof(icmp_t)

/* ICMPv6 type value  */
#define ICMP6_TYPE_DEST_UNREACH 1      /* Destination Unreachable */
#define ICMP6_TYPE_PKT_TOO_BIG 2       /* Packet Too Big */
#define ICMP6_TYPE_TIME_EXCEEDED 3     /* Time Exceeded */
#define ICMP6_TYPE_PARAM_PROB 4        /* Parameter Problem */
#define ICMP6_TYPE_ECHO_REQ 128        /* Echo Request */
#define ICMP6_TYPE_ECHO_REP 129        /* Echo Reply */
#define ICMP6_TYPE_ROUTER_SOLIC 133    /* ND Router Solicitation */
#define ICMP6_TYPE_ROUTER_ADV 134      /* ND Router Advertisement */
#define ICMP6_TYPE_NEIGH_SOL 135       /* ND Neighbor Solicitation */
#define ICMP6_TYPE_NEIGH_ADV 136       /* ND Neighbor Advertisement */
#define ICMP6_TYPE_REDIRECT 137        /* ND Redirect */
#define ICMP6_TYPE_ROUTER_RENUM 138    /* Router Renumbering */

void register_icmp6();

#endif /* GROINK_ICMP6_H*/
