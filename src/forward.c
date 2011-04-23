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
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "debug.h"
#include "forward.h"
#include "globals.h"
#include "netutil.h"
#include "packet.h"
#include "protos_name.h"
#include "protocols/ethernet.h"
#include "protocols/ipv4.h"
#include "protocols/tcp.h"
#include "protocols/udp.h"

void init_packet_forward_module()
{
  if (gbls->mitm == NULL)
    return;

  gbls->sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

  if (gbls->sockfd == -1)
    fatal(__func__, "socket creation failed");

  debug("packet forwarding module initialized");

  // TODO: IPv6 socket
}

void destroy_packet_forward_module()
{
  if (gbls->sockfd != -1) {
    close(gbls->sockfd);
    gbls->sockfd = -1;
    
    debug("packet forwarding module destroyed");
  }

  // TODO: IPv6 socket
}

static void ip_forward(packet_t *p)
{
  struct sockaddr_in sin;
  ipv4_t *ip = NULL;
  size_t pkt_len = 0;

  if (packet_contains_header(p, PROTO_NAME_ETHER))
    pkt_len = p->len - ETHER_HDR_LEN;
  else
    pkt_len = p->len;  /* IP raw packet, no link layer */
  
  ip = (ipv4_t *)(packet_get_header(p, PROTO_NAME_IPV4))->data;
  
  memset(&sin, 0, sizeof(sin));
  sin.sin_family  = AF_INET;
  sin.sin_addr.s_addr = ip->dest_addr;
  
  if (packet_contains_header(p, PROTO_NAME_TCP)) {
    /* Set port for TCP */
    tcp_t *tcp = (tcp_t *)(packet_get_header(p, PROTO_NAME_TCP))->data;
    sin.sin_port = tcp->dest_port;
  } else if (packet_contains_header(p, PROTO_NAME_UDP)) {
    /* Set port for UDP */
    udp_t *udp = (udp_t *)(packet_get_header(p, PROTO_NAME_UDP))->data;
    sin.sin_port = udp->dest_port;
  }
  
  sendto(gbls->sockfd, (void *)ip, pkt_len, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr));
}

/* static void ip6_forward(packet_t *p) */
/* { */
/*   // TODO */
/* } */

void packet_forward(packet_t *p)
{
  if (PKT_HAS_FLAG(p, PACKET_FLAG_DROP))
    return;
  
  /* Forward only IP packets */
  if (packet_contains_header(p, PROTO_NAME_IPV4)) {
      /* Skip my packets */
      if (strcmp(p->net_dstaddr, gbls->net_addr) != 0 && strcmp(p->hw_dstaddr, gbls->link_addr) == 0) {
	if (packet_contains_header(p, PROTO_NAME_IPV4))
	  ip_forward(p);
	/* else if (packet_contains_header(p, PROTO_NAME_IPV6)) */
	/*   ip6_forward(p); */
      }
  }
}
