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
#ifndef GROINK_ICMP_H
#define GROINK_ICMP_H

#include "base.h"
#include "packet.h"

/*
 * RFC 792 - ICMPv4 HEADER
 * =======================
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

typedef struct _grk_icmp {
  _uint8 type;
  _uint8 code;
  _uint16 cksum;
} icmp_t;

typedef struct _grk_icmp_echo_body {
  _uint16 id;
  _uint16 seq;
} icmp_body_t;

#define ICMP_HDR_LEN sizeof(icmp_t)

/* ICMP type value  */
#define ICMP_TYPE_ECHOREPLY        0           /* Echo Reply */
#define ICMP_TYPE_DEST_UNREACH     3           /* Destination Unreachable */
#define ICMP_TYPE_SOURCE_QUENCH    4           /* Source Quench */
#define ICMP_TYPE_REDIRECT         5           /* Redirect (change route) */
#define ICMP_TYPE_ECHO             8           /* Echo Request */
#define ICMP_TYPE_ROUTER_ADV       9           /* Router Advertisement */
#define ICMP_TYPE_ROUTER_SOL       10          /* Router Solicitation */
#define ICMP_TYPE_TIME_EXCEEDED	   11          /* Time Exceeded */
#define ICMP_TYPE_PARAM_PROB	   12          /* Parameter Problem */
#define ICMP_TYPE_TIMESTAMP        13          /* Timestamp Request */
#define ICMP_TYPE_TIMESTAMPREPLY   14          /* Timestamp Reply */
#define ICMP_TYPE_INFO_REQUEST     15          /* Information Request */
#define ICMP_TYPE_INFO_REPLY       16          /* Information Reply */
#define ICMP_TYPE_ADDRESS          17          /* Address Mask Request */
#define ICMP_TYPE_ADDRESSREPLY     18          /* Address Mask Reply */
#define ICMP_TYPE_TRACEROUTE       30          /* Traceroute */

/* Codes for UNREACH. */
#define ICMP_UN_NET_UNREACH     0	/* Network Unreachable */
#define ICMP_UN_HOST_UNREACH	1	/* Host Unreachable */
#define ICMP_UN_PROT_UNREACH	2	/* Protocol Unreachable	*/
#define ICMP_UN_PORT_UNREACH	3	/* Port Unreachable */
#define ICMP_UN_FRAG_NEEDED	4	/* Fragmentation Needed/DF set */
#define ICMP_UN_SR_FAILED	5	/* Source Route failed */
#define ICMP_UN_NET_UNKNOWN	6
#define ICMP_UN_HOST_UNKNOWN	7
#define ICMP_UN_HOST_ISOLATED	8
#define ICMP_UN_NET_ANO		9
#define ICMP_UN_HOST_ANO	10
#define ICMP_UN_NET_UNR_TOS	11
#define ICMP_UN_HOST_UNR_TOS	12
#define ICMP_UN_PKT_FILTERED	13	/* Packet filtered */
#define ICMP_UN_PREC_VIOLATION	14	/* Precedence violation */
#define ICMP_UN_PREC_CUTOFF	15	/* Precedence cut off */

/* Codes for REDIRECT. */
#define ICMP_REDIR_NET		0	/* Redirect Net	*/
#define ICMP_REDIR_HOST		1	/* Redirect Host */
#define ICMP_REDIR_NETTOS	2	/* Redirect Net for TOS	*/
#define ICMP_REDIR_HOSTTOS	3	/* Redirect Host for TOS */

/* Codes for TIME_EXCEEDED. */
#define ICMP_TEXC_TTL		0	/* TTL count exceeded */
#define ICMP_TEXC_FRAGTIME	1	/* Fragment Reass time exceeded	*/

void register_icmp();

#endif /* GROINK_ICMP_H */
