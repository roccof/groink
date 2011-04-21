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
#include <arpa/inet.h>
#include <pcap.h>
#include <string.h>
#include <unistd.h>

#include "base.h"
#include "debug.h"
#include "decoder.h"
#include "globals.h"
#include "hook.h"
#include "host.h"
#include "inject.h"
#include "netutil.h"
#include "packet.h"
#include "protocols/arp.h"
#include "threads.h"
#include "utlist.h"
#include "protos_name.h"

#define HOST_CAP_THREAD_NAME "host_target_capture"

static int num_hosts = 0;

static int contains_host(host_t *h)
{
  host_t *curr = NULL;

  LL_FOREACH (gbls->hosts, curr)
    if (strcmp(h->hw_addr, curr->hw_addr) == 0 && 
	strcmp(h->net_addr, curr->net_addr) == 0)
      return 1;
  return 0;
}

/* Get ARP reply */
static void arp_received_cb(hookdata_t *data)
{
  packet_t *p = NULL;
  arp_t *arp = NULL;
  arp_ethip_t *ethip = NULL;
  header_t *header = NULL;
  char *mac_addr = NULL;
  char *ip_addr = NULL;
  _uint32 *ip_addr_bin = NULL;
  host_t *h = NULL;

  if (data->type != HOOKDATA_PACKET)
    bug(__func__, "invalid hook data on HOOK_ARP event");

  p = (packet_t *)data->data;
  header = packet_get_header(p, PROTO_NAME_ARP);

  if (header == NULL)
    bug(__func__, "invalid packet, there isn't ARP header");

  arp = (arp_t *)header->data;
  ethip = (arp_ethip_t *)(arp + 1);

  /* Process only Arp Reply packets */
  if (ntohs(arp->opcode) != ARP_OP_REPLY)
    return;

  mac_addr = ether_addr_ntoa(ethip->sha);

  ip_addr_bin = (_uint32 *)&ethip->spa;
  ip_addr = ip_addr_ntoa(*ip_addr_bin);

  h = (host_t *)safe_alloc(sizeof(host_t));
  h->net_addr = strdup(ip_addr);
  h->hw_addr = strdup(mac_addr);

  if (!contains_host(h)) {
    LL_APPEND(gbls->hosts, h);
    num_hosts++;
  } else {
    free(h->hw_addr);
    free(h->net_addr);
    free(h);
  }

  free(mac_addr);
  free(ip_addr);
}

static void proc_packet_cb(u_char *user, const struct pcap_pkthdr *header, const u_char *bytes)
{
  packet_t *p = NULL;

  /* Skip truncated packet */
  if (header->len > gbls->snaplen)
    return;

  p = packet_new((_uchar *)bytes, header->len);

  /* Decode packet */
  start_decoding(p);

  packet_free(p);
}

static void *capture_thread_cb(void *arg)
{
  THREAD_DEFAULT_INIT;
  
  pcap_loop(gbls->pcap, 0, &proc_packet_cb, NULL);

  return NULL;
}

void build_hosts_list() // TODO: ipv6 support
{
  int num = 0;
  int tot = 0;
  _uint32 ip = 0;
  _uint32 netmask = 0;
  pthread_t thread = 0;

  if (gbls->link_addr == NULL) {
    warning("the iface %s has no mac address associated, skipping hosts scanning...", gbls->iface);
    return;
  }

  if (gbls->net_addr == NULL && gbls->netmask == NULL) {
    warning("the iface %s has no ip address and netmask associated, skipping hosts scanning...", gbls->iface);
    return;
  }

  message("Scanning hosts...");

  num_hosts = 0;

  ip = ip_addr_aton(gbls->net_addr);
  netmask = ip_addr_aton(gbls->netmask);

  /* Number of host in the subnet */
  tot = ~ntohl(netmask);

  /* Get only packet received by the device */
  pcap_setdirection(gbls->pcap, PCAP_D_IN);

  thread_new(HOST_CAP_THREAD_NAME, &capture_thread_cb, NULL);

  hook_register(HOOK_ARP, &arp_received_cb);

  /* Create a list with all the ips of the subnet */
  for (num=0; num<tot; num++) {
    char *hostip = NULL;
    
    _uint32 ip_bin = (ip & netmask) | htonl(num);
    
    hostip = ip_addr_ntoa(*((_uint32 *)&ip_bin));
    
    /* Send ARP request to retrieve mac address */
    inject_arp_request(gbls->link_addr, gbls->net_addr, ETHER_BROADCAST, hostip);
    
    free(hostip);
    
    usleep(ARP_STORM_WAIT * 1000);
  }

  sleep(1); /* Wait delayed packet */
  
  hook_unregister(HOOK_ARP, &arp_received_cb);
  
  thread = thread_id_from_name(HOST_CAP_THREAD_NAME);
  
  if (thread != 0)
    thread_stop(thread);
  
  /* Restore direction */
  pcap_setdirection(gbls->pcap, PCAP_D_INOUT);

  message("Found %d hosts active of %d hosts", num_hosts, tot);
}

void free_hosts_list()
{
  host_t *curr = NULL, *tmp = NULL;
  
  num_hosts = 0;

  LL_FOREACH_SAFE (gbls->hosts, curr, tmp) {
    LL_DELETE(gbls->hosts, curr);

    free(curr->net_addr);
    free(curr->hw_addr);
    free(curr);
    curr = NULL;
  }
}
