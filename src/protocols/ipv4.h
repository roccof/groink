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
#ifndef GROINK_IPV4_H
#define GROINK_IPV4_H

#include "base.h"
#include "packet.h"

/*
 * RFC 791 - IP HEADER
 * ===================
 *
 * 0                   1                   2                   3   
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |Version|  IHL  |Type of Service|          Total Length         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Identification        |Flags|      Fragment Offset    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Time to Live |    Protocol   |         Header Checksum       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                       Source Address                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Destination Address                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Options                    |    Padding    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *
 * Those sources are based on linux <netinet/ip.h>
 */

typedef struct _grk_ipv4
{
  _uint8 vihl;                    /* version, internet header length */
#define IPV4_VERS(ipv4_hdr) (((ipv4_hdr)->vihl & 0xf0) >> 4)
#define IPV4_IHL(ipv4_hdr) ((ipv4_hdr)->vihl & 0x0f)
  _uint8 tos;                     /* type of service */
  _uint16 len;                    /* total length */
  _uint16 id;                     /* identification */
  _uint16 frag_offset;            /* flags && fragment offset */
#define	IPV4_RF 0x8000            /* reserved fragment flag */
#define IPV4_DF 0x4000            /* dont fragment flag */
#define IPV4_MF 0x2000            /* more fragments flag */
#define IPV4_FRAG 0x1fff          /* mask for fragmenting bits */
  _uint8 ttl;                     /* time to live */
  _uint8 proto;                   /* protocol */
  _uint16 checksum;               /* checksum */
  _uint32 src_addr;               /* source address */
  _uint32 dest_addr;              /* destination address */
} ipv4_t;

/* IPv4 header length in byte */
#define IPV4_HDR_LEN(ip) (IPV4_IHL((ip)) * 4)

#define	IPV4_VERSION 4        /* IP version number */
#define	IPV4_MAXPACKET 65535  /* maximum packet size */
#define	IPV4_MAXTTL 255       /* maximum time to live (seconds) */
#define	IPV4_DEFTTL 64        /* default ttl, from RFC 1340 */
#define	IPV4_MSS 576          /* default maximum segment size */
#define IPV4_ADDR_LEN 4       /* address length (bytes)  */

/*
 * Type of Service
 *
 *    0     1     2     3     4     5     6     7
 * +-----+-----+-----+-----+-----+-----+-----+-----+
 * |                 |     |     |     |     |     |
 * |   PRECEDENCE    |  D  |  T  |  R  |  0  |  0  |
 * |                 |     |     |     |     |     |
 * +-----+-----+-----+-----+-----+-----+-----+-----+
 */

/* TOS BIT MASK */
#define IPV4_TOS_MASK 0x1c
#define	IPV4_TOS(tos) ((tos) & IPV4_TOS_MASK)
#define IPV4_TOS_DELAY 0x10
#define IPV4_TOS_THROUGHPUT 0x08
#define IPV4_TOS_RELIBILITY 0x04
#define	IPV4_TOS_PREC_MASK 0xe0
#define	IPV4_TOS_PREC(tos) ((tos) & IPV4_TOS_PREC_MASK)

/* TOS PRECENDENCE  */
#define	IPV4_TOS_PREC_NETCONTROL 0xe0
#define	IPV4_TOS_PREC_INTERNETCONTROL 0xc0
#define	IPV4_TOS_PREC_CRITIC_ECP 0xa0
#define	IPV4_TOS_PREC_FLASHOVERRIDE 0x80
#define	IPV4_TOS_PREC_FLASH 0x60
#define	IPV4_TOS_PREC_IMMEDIATE 0x40
#define	IPV4_TOS_PREC_PRIORITY 0x20
#define	IPV4_TOS_PREC_ROUTINE 0x00

/* TOS DELAY */
#define IPV4_TOS_DELAY_NORMAL 0x00
#define IPV4_TOS_DELAY_LOW IPV4_TOS_DELAY

/* TOS THROUGHPUT */
#define IPV4_TOS_THROUG_NORMAL 0x00
#define IPV4_TOS_THROUG_LOW IPV4_TOS_THROUGHPUT

/* TOS RELIBILITY */
#define IPV4_TOS_REL_NORMAL 0x00
#define IPV4_TOS_REL_LOW IPV4_TOS_RELIBILITY

/* PROTOCOL  */
#define IPV4_PROTO_ICMP 1
#define IPV4_PROTO_TCP 6
#define IPV4_PROTO_UDP 17

/* OPTION */
#define IPV4_OPT_LEN(ip) (IPV4_HDR_LEN((ip)) - sizeof(IPV4))

#define IPV4_OPT_COPY 0x80
#define	IPV4_OPT_CLASS_MASK 0x60
#define	IPV4_OPT_NUMBER_MASK 0x1f

#define IPV4_OPT_COPIED(opt) ((opt) & IPV4_OPT_COPY)
#define	IPOPT_CLASS(opt) ((opt) & IPV4_OPT_CLASS_MASK)
#define	IPOPT_NUMBER(opt) ((opt) & IPV4_OPT_NUMBER_MASK)

/* #define	IPV4_OPT_CLASS_CONTROL 0x00 */
/* #define	IPV4_OPT_CLASS_RESERVED1 0x20 */
/* #define	IPV4_OPT_CLASS_DEBMEAS 0x40 */
/* #define	IPV4_OPT_CLASS_MEASUREMENT IPOPT_DEBMEAS */
/* #define	IPV4_OPT_CLASS_RESERVED2 0x60 */

/* IPv4 decoding error */
#define ERR_IPV4_BAD_VERSION 0x80

void register_ipv4();

#endif /* GROINK_IPV4_H */
