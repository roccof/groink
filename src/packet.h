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
#ifndef GROINK_PACKET_H
#define GROINK_PACKET_H

#include "base.h"

/* Header protocols */
typedef enum {
  PROTO_ETHER,              /* Ethernet */
  PROTO_IEEE80211,          /* IEEE 802.11 wireless lan */
  PROTO_IEEE80211_RADIO,    /* Link layer IEEE 802.11 (radiotap) */
  PROTO_PPP,                /* Point to Point Protocol */
  PROTO_PPPOE,              /* PPP over Ethernet */
  PROTO_IPV4,               /* IPv4 */
  PROTO_IPV6,               /* IPv6 */
  PROTO_ARP,                /* ARP / Reverse ARP */
  PROTO_TCP,                /* TCP */
  PROTO_UDP,                /* UDP */
  PROTO_ICMP,               /* ICMPv4 */
  PROTO_ICMPV6,             /* ICMPv6 */
  PROTO_RAW,                /* Raw protocol, contains raw bytes 
			       (generally used for unknown protocols) */
  PROTO_HTTP                /* HTTP */
} Proto;

typedef enum {
  PTYPE_ARP,
  PTYPE_IPV4,
  PTYPE_IPV6
} PacketType;

/* Header structure */
typedef struct _header {
  Proto proto;              /* Protocol */
  int len;                  /* Lenght */
  _uchar *data;             /* Raw header data */
  _uint8 decoding_errors;   /* Decoding errors bitmap */
  struct _header *next;     /* Next header */
  struct _packet *packet;   /* The packet that contains this header */
} Header;

#define ADD_FLAG(p, f) ((p)->flags |= (f))
#define REMOVE_FLAG(p, f) ((p)->flags &= ~(f))
#define HAS_FLAG(p, f) (((p)->flags & (f)) == (f))

#define PACKET_FLAG_DROP 0x80            /* Drop the packet */
#define PACKET_FLAG_MODIFIED 0x40        /* The packet was modified, recalculate the cksum */
#define PACKET_FLAG_UNMODIFICABLE 0x20   /* The packet is unmodificable */
#define PACKET_FLAG_CAPTURED 0x10        /* Captured packet */
#define PACKET_FLAG_DECODED 0x08         /* Indicates that the packet was decoded */
#define PACKET_FLAG_DISSECTED 0x04       /* Indicates that the packet was dissected */
#define PACKET_FLAG_DECODE_ERR 0x03      /* Indicates that there is an error while packet decoding */
#define PACKET_FLAG_DISSECT_ERR 0x01     /* Indicates that there is an error while packet dissecting */

/* Packet object structure */
typedef struct _packet {
  _uchar *rawdata;               /* Raw data */
  _uint32 len;                   /* Packet length*/
  _uchar *edit_rawdata;          /* This buffer contains the packet raw data of the packet 
				    only if it was modified */
  _uint32 edit_len;              /* Length of the modified packet data */
  struct _header *headers;       /* Headers list */
  int num_headers;               /* Number of headers */
  _uint8 flags;                  /* Flags bit mask */
  PacketType type;               /* Packet type: IPv4 or IPv6 */
  char *hw_dstaddr;              /* Destination hw address */
  char *hw_srcaddr;              /* Source hw address */
  char *net_srcaddr;             /* Source net address */
  char *net_dstaddr;             /* Destination net address*/
} Packet;

/*
 * Raw packet structure used from capture engine for
 * save captured packet
 */
typedef struct _raw_packet {
  unsigned char *data;      /* Pointer of packet data */
  size_t len;               /* Packet length */
} RawPacket;


Header *packet_add_header(Packet *p, Proto proto, void *data, size_t len);
void packet_init(Packet *p);
void packet_free(Packet *p);
Header *packet_get_header(Packet *p, Proto proto);
int packet_contains_header(Packet *p, Proto proto);

#endif /* GROINK_PACKET_H */
