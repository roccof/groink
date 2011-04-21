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
#include <string.h>
#include <pcap.h>

#include "inject.h"
#include "globals.h"
#include "inject.h"
#include "netutil.h"
#include "packet.h"
#include "protocols/ethernet.h"
#include "protocols/arp.h"
#include "protos_name.h"

/* Send a packet over network */
void inject(packet_t *p)
{
  pcap_sendpacket(gbls->pcap, p->data, p->len);
}

/* Send ARP Reply packet */
void inject_arp_reply(char *eth_src, char *ip_src, char *eth_target, char *ip_target)
{
  packet_t *p = NULL;
  ether_t *ether = NULL;
  arp_t *arp;

  p = packet_new_empty();

  ether = build_ethernet(eth_src, eth_target, ETHER_TYPE_ARP);
  packet_append_header(p, PROTO_NAME_ETHER, (void *)ether, ETHER_HDR_LEN);

  arp = build_arp_ethip(ARP_OP_REPLY, eth_src, ip_src, eth_target, ip_target);
  packet_append_header(p, PROTO_NAME_ARP, (void *)arp, sizeof(arp_t) + sizeof(arp_ethip_t));

  inject(p);

  packet_free(p);
  free(ether);
  free(arp);
}

/* Send ARP Request packet */
void inject_arp_request(char *eth_src, char *ip_src, char *eth_target, char *ip_target)
{
  packet_t *p = NULL;
  ether_t *ether = NULL;
  arp_t *arp;

  p = packet_new_empty();

  ether = build_ethernet(eth_src, eth_target, ETHER_TYPE_ARP);
  packet_append_header(p, PROTO_NAME_ETHER, (void *)ether, ETHER_HDR_LEN);

  arp = build_arp_ethip(ARP_OP_REQUEST, eth_src, ip_src, eth_target, ip_target);
  packet_append_header(p, PROTO_NAME_ARP, (void *)arp, sizeof(arp_t) + sizeof(arp_ethip_t));

  inject(p);

  packet_free(p);
  free(ether);
  free(arp);
}

/* Send custom ARP message */
void inject_arp(char *eth_src, char *eth_dst, _uint16 opcode, char *sha, char *spa, char *tha, char *tpa)
{
  packet_t *p = NULL;
  ether_t *ether = NULL;
  arp_t *arp;

  p = packet_new_empty();

  ether = build_ethernet(eth_src, eth_dst, ETHER_TYPE_ARP);
  packet_append_header(p, PROTO_NAME_ETHER, (void *)ether, ETHER_HDR_LEN);

  arp = build_arp_ethip(opcode, sha, spa, tha, tpa);
  packet_append_header(p, PROTO_NAME_ARP, (void *)arp, sizeof(arp_t) + sizeof(arp_ethip_t));

  inject(p);

  packet_free(p);
  free(ether);
  free(arp);
}
