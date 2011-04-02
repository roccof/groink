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
#ifndef GROINK_ETHERNET_H
#define GROINK_ETHERNET_H

#include "base.h"
#include "packet.h"

/*
 * Ethernet frame:
 * +--------------+-------------+-----------+---------+
 * |              |             |           |         |
 * | dest address | src address |   type    | payload |
 * |  (14 bytes)  |  (14 bytes) | (8 bytes) |         |
 * |              |             |           |         |
 * +--------------+-------------+-----------+---------+
 *
 * Those sources are based on linux <net/ethernet.h>
 */

#define ETHER_ADDR_LEN   6  /* bytes in the address */
#define ETHER_HDR_LEN   14  /* bytes in the header */

typedef struct _grk_ethernet
{
  _uint8 dest_addr[ETHER_ADDR_LEN];   /* destination mac address */
  _uint8 src_addr[ETHER_ADDR_LEN];    /* source mac address */
  _uint16 type;                       /* packet type */
} ether_t;

/* Ethernet decoding error */
#define UNKNOWN_ETHER_TYPE 0x80

/* Ethernet protocol ID's */
#define	ETHER_TYPE_IP		0x0800		/* IP */
#define	ETHER_TYPE_ARP		0x0806		/* Address resolution */
#define	ETHER_TYPE_REVARP	0x8035		/* Reverse ARP */
#define	ETHER_TYPE_IPV6		0x86dd		/* IP protocol version 6 */
#define ETHER_TYPE_PPP          0x880b          /* Point to Point protocol */
#define ETHER_TYPE_PPPOED       0x8863          /* PPP over Ethernet discovery stage */
#define ETHER_TYPE_PPPOES       0x8864          /* PPP over Ethernet session stage */
#define ETHER_TYPE_LOOPBACK	0x9000		/* Used to test interfaces */

ether_t *build_ethernet(char *, char *, _uint16);
void register_ether();

#endif /* GROINK_ETEHRNET_H */
