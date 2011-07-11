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

/* Header structure */
typedef struct _grk_header {
  char *proto;                 /* Protocol */
  size_t len;                  /* Lenght */
  _uchar *data;                /* Raw header data */
  struct _grk_header *next;    /* Next header */
  struct _grk_header *prev;    /* Previous header */
  struct _grk_packet *packet;  /* The packet that contains this header */
} header_t;

#define PKT_ADD_FLAG(p, f) ((p)->flags |= (f))
#define PKT_REMOVE_FLAG(p, f) ((p)->flags &= ~(f))
#define PKT_HAS_FLAG(p, f) (((p)->flags & (f)) == (f))

#define PACKET_FLAG_DROP 0x80            /* Drop the packet */
#define PACKET_FLAG_MODIFIED 0x40        /* The packet was modified */
#define PACKET_FLAG_UNMODIFICABLE 0x20   /* The packet is unmodificable */
#define PACKET_FLAG_CAPTURED 0x10        /* Captured packet */
#define PACKET_FLAG_DECODED 0x08         /* Indicates that the packet was decoded */
#define PACKET_FLAG_DECODE_ERR 0x04      /* Indicates that there is an error 
					    while packet decoding */

/* Packet object structure */
typedef struct _grk_packet {
  _uchar *data;                   /* Packet data */
  size_t len;                     /* Packet length*/
  header_t *headers;              /* Headers list */
  int num_headers;                /* Number of headers */
  _uint8 flags;                   /* Flags bit mask */
  _uint8 dec_err[MAX_ERR_LEN];    /* Decoding error */
  char *hw_dstaddr;               /* Destination hw address */
  char *hw_srcaddr;               /* Source hw address */
  char *net_srcaddr;              /* Source net address */
  char *net_dstaddr;              /* Destination net address */
} packet_t;

packet_t *packet_new(_uint8 *data, size_t len);
packet_t *packet_new_empty();
void packet_free(packet_t *p);
header_t *packet_append_header(packet_t *p, char *proto, _uint8 *data, size_t len);
header_t *packet_get_header(packet_t *p, char *proto);
int packet_contains_header(packet_t *p, char *proto);

#endif /* GROINK_PACKET_H */
