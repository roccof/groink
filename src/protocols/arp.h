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
#ifndef GROINK_ARP_H
#define GROINK_ARP_H

#include "base.h"
//#include "ipv4.h"
#include "ethernet.h"

/*
 * RFC826
 *
 * Those sources are based on linux <net/if_arp.h>
 */

typedef struct _arp
{
  _uint16 hrd;       /* Format of hardware address */
  _uint16 pro;       /* Format of protocol address */
  _uint8 hln;        /* Length of hardware address */
  _uint8 pln;        /* Length of protocol address */
  _uint16 opcode;    /* ARP opcode (command) */
} arp_t;

/* tmp */
#define IPV4_ADDR_LEN 4

/* Ethernet arp additional info (only into Ethernet networks) */
typedef struct _arp_ethip
{
  _uint8 sha[ETHER_ADDR_LEN];   /* sender hardware address */
  _uint8 spa[IPV4_ADDR_LEN];    /* sender protocol address */
  _uint8 tha[ETHER_ADDR_LEN];   /* target hardware address */
  _uint8 tpa[IPV4_ADDR_LEN];    /* target protocol address */
} arp_ethip_t;

/* ARP protocol opcodes */
#define	ARP_OP_REQUEST      1	 /* ARP request */
#define	ARP_OP_REPLY        2	 /* ARP reply */
#define	ARP_OP_RREQUEST     3	 /* RARP request */
#define	ARP_OP_RREPLY       4	 /* RARP reply */
#define	ARP_OP_InREQUEST    8	 /* InARP request */
#define	ARP_OP_InREPLY      9    /* InARP reply */
#define	ARP_OP_NAK          10	 /* (ATM)ARP NAK */

/* ARP protocol HARDWARE identifiers */
#define ARP_HRD_ETHER 1	         /* Ethernet 10/100Mbps */

/* ARP protocol PROTOCOL indentifiers */
#define ARP_PROTO_IPV4 ETHER_TYPE_IP

void register_arp();
/* arp_t *build_arp(_uint16 hrd, _uint16 pro, _uint8 hln, _uint8 pln, _uint16 opcode); */
arp_t *build_arp_ethip(_uint16 opcode, char *sha, char *spa, char *tha, char *tpa);

#endif /* GROINK_ARP_H */
