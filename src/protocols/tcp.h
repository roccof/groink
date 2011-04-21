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
#ifndef GROINK_TCP_H
#define GROINK_TCP_H

#include "base.h"
#include "packet.h"

/*
 * RFC 793 - TCP HEADER
 * ====================
 *
 *  0                   1                   2                   3   
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          Source Port          |       Destination Port        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                        Sequence Number                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Acknowledgment Number                      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Data |           |U|A|P|R|S|F|                               |
 * | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
 * |       |           |G|K|H|T|N|N|                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           Checksum            |         Urgent Pointer        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Options                    |    Padding    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                             data                              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Those sources are based on linux <netinet/tcp.h>
 */

typedef struct _tcp {
  _uint16 src_port;        /* Source port */
  _uint16 dest_port;       /* Destination port */
  _uint32 seq;             /* Sequence number */
  _uint32 ack;             /* Acknowledgment number */
#if defined BENDIAN
  _uint8 offset:4;         /* Data offset */
  _uint8 unused:4;         /* Unused space */
#elif defined LENDIAN
  _uint8 unused:4;         /* Unused space */
  _uint8 offset:4;         /* Data offset */
#endif
  _uint8 flags;            /* Flags with 2 bit of unused space */
#define TCP_FIN 0x01       /* FIN flasg */
#define TCP_SYN 0x02       /* SYN flag */
#define TCP_RST 0x04       /* RST flag */
#define TCP_PUSH 0x08      /* PUSH flag */
#define TCP_ACK 0x10       /* ACK flag */
#define TCP_URG 0x20       /* URG flag */
  _uint16 win;             /* Window */
  _uint16 checksum;        /* Cecksum */
  _uint16 urgp;            /* Urgent pointer */
} tcp_t;

/*
 * The lenght of TCP header is the data offset (wich indicates the number
 * of 32 bit words in the TCP header) multiplied for 4 (octects in a 32 bit words).
 * The lenght is expressed in byte.
 */
#define TCP_HDR_LEN(tcp_hdr) ((tcp_hdr)->offset * 4)

/* 
 * Default maximum segment size for TCP.
 * With an IP MSS of 576, this is 536,
 * but 512 is probably more convenient.
 * This should be defined as MIN(512, IP_MSS - sizeof (struct tcpiphdr)).
 */
/* #define TCP_MSS MIN(512, (IPV4_MSS - sizeof(TCP))) */
#define TCP_MSS 512
#define TCP_MAXWIN 65535	/* largest value for (unscaled) window */
#define TCP_MAX_WINSHIFT 14	/* maximum window shift */

#define TCP_OPT_EOL 0
#define TCP_OPT_NOP 1
#define TCP_OPT_MAXSEG 2
#define TCP_OLEN_MAXSEG 4
#define TCP_OPT_WINDOW 3
#define TCP_OLEN_WINDOW 3

/* #define TCP_OPT_SACK_PERMITTED 4 /\* Experimental *\/ */
/* #define TCP_OLEN_SACK_PERMITTED 2 */
/* #define TCP_OPT_SACK 5 /\* Experimental *\/ */
/* #define TCP_OPT_TIMESTAMP 8 */
/* #define TCP_OLEN_TIMESTAMP 10 */
/* #define TCP_OLEN_TSTAMP_APPA (TC_POLEN_TIMESTAMP+2) /\* appendix A *\/ */
/* #define TCP_OPT_TSTAMP_HDR	\ */
/*     (TCP_OPT_NOP<<24|TCP_OPT_NOP<<16|TCP_OPT_TIMESTAMP<<8|TCP_OLEN_TIMESTAMP) */

void register_tcp();

#endif /* GROINK_TCP_H */
