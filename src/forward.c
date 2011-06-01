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
#include "protocols/ipv6.h"
#include "protocols/tcp.h"
#include "protocols/udp.h"
#include "utlist.h"

static int sockfd = -1;
static int sockfd6 = -1;

void packet_forward_module_init()
{
  if (gbls->mitm == NULL)
    return;

  sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (sockfd == -1)
    fatal(__func__, "IPv4 socket creation failed");

#ifdef SIOCGIFNETMASK_IN6
  sockfd6 = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
  if (sockfd6 == -1)
    fatal(__func__, "IPv6 socket creation failed");
#endif

  debug("packet forwarding module initialized");
}

void packet_forward_module_destroy()
{
  int show = 0;

  if (sockfd != -1 || sockfd6 != -1)
    show = 1;

  if (sockfd != -1) {
    close(sockfd);
    sockfd = -1;
  }

#ifdef SIOCGIFNETMASK_IN6
  if (sockfd6 != -1) {
    close(sockfd6);
    sockfd6 = -1;
  }
#endif

  if (show)
    debug("packet forwarding module destroyed");
}

static void ip_forward(packet_t *p)
{
  struct sockaddr_in sin;
  ipv4_t *ip = NULL;
  size_t pkt_len = 0;

  /* Skip my packets */
  if (strncmp(p->net_dstaddr, gbls->net_addr, strlen(p->net_dstaddr)))
      return;

  /* XXX FIXME */
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
  
  sendto(sockfd, (void *)ip, pkt_len, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr));
}

static void ip6_forward(packet_t *p)
{
  struct sockaddr_in6 sin6;
  ipv6_t *ip = NULL;
  size_t pkt_len = 0;
  struct _grk_ip6_addrs *net6 = NULL;

  /* Skip my packets */
  LL_FOREACH(gbls->net6_addrs, net6)
    if (strncmp(p->net_dstaddr, net6->addr, strlen(p->net_dstaddr)) == 0)
      return;

  /* XXX FIXME */
  if (packet_contains_header(p, PROTO_NAME_ETHER))
    pkt_len = p->len - ETHER_HDR_LEN;
  else
    pkt_len = p->len;  /* IP raw packet, no link layer */
  
  ip = (ipv6_t *)(packet_get_header(p, PROTO_NAME_IPV6))->data;
  
  memset(&sin6, 0, sizeof(sin6));
  sin6.sin6_family  = AF_INET6;
  memcpy(sin6.sin6_addr.s6_addr, ip->dst_addr, IPV6_ADDR_LEN);
  
  if (packet_contains_header(p, PROTO_NAME_TCP)) {
    /* Set port for TCP */
    tcp_t *tcp = (tcp_t *)(packet_get_header(p, PROTO_NAME_TCP))->data;
    sin6.sin6_port = tcp->dest_port;
  } else if (packet_contains_header(p, PROTO_NAME_UDP)) {
    /* Set port for UDP */
    udp_t *udp = (udp_t *)(packet_get_header(p, PROTO_NAME_UDP))->data;
    sin6.sin6_port = udp->dest_port;
  }
  
  sendto(sockfd6, (void *)ip, pkt_len, 0, (struct sockaddr *)&sin6, sizeof(struct sockaddr));
}

void packet_forward(packet_t *p)
{
  if (PKT_HAS_FLAG(p, PACKET_FLAG_DROP))
    return;
  
  /* Forward only IP packets */
  if (packet_contains_header(p, PROTO_NAME_IPV4))
    ip_forward(p);
  else if (packet_contains_header(p, PROTO_NAME_IPV6))
    ip6_forward(p);
}
