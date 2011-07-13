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
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <pcap.h>

#include "config.h"
#include "base.h"
#include "debug.h"
#include "globals.h"
#include "threads.h"
#include "parse_options.h"
#include "hook.h"
#include "protos.h"
#include "script_engine.h"
#include "pcap_util.h"
#include "forward.h"
#include "decoder.h"
#include "packet.h"
#include "inject.h"
#include "iface.h"
#include "ouidb.h"

static pcap_t *pcap = NULL;

static void cleanup()
{
  struct pcap_stat ps;

  debug("cleaning up...");
  
  if (pcap != NULL) {
    pcap_breakloop(pcap);
    debug("sniffing stopped");

    if (pcap_stats(pcap, &ps) != -1)
      debug("cap/recv/drop packet: %d/%d/%d", 
	    gbls->cap_packets, ps.ps_recv, ps.ps_drop);
    
    pcap_close(pcap);
  }

  se_close();
  mitm_stop();
  inject_cleanup();
  ouidb_free();
  protos_destroy();
  packet_forward_module_destroy();
  threads_manager_destroy();
  hook_cleanup();
  globals_destroy();
}

static void signal_handler_cb(int signal)
{
  exit(EXIT_SUCCESS);
}

static void process_packet(u_char *user, const struct pcap_pkthdr *header, const u_char *bytes)
{
  packet_t *p = NULL;
  hookdata_t *hookdata = NULL;

  if (header->len == 0 || bytes == NULL) {
      /*
       * XXX:
       *     If header->len is 0, header->caplen is
       *     greater than zero. Why???? oO
       */
      return;
    }

  /* Skip truncated packets */
  if (header->len > gbls->snaplen) {
    debug("captured truncated packet [pkt-len: %d, snaplen: %d], skipping...",
	  header->len, gbls->snaplen);
    return;
  }
  
  gbls->cap_packets++;
  
  p = packet_new((_uchar *)bytes, header->len);
  PKT_ADD_FLAG(p, PACKET_FLAG_CAPTURED);
  
  if (gbls->decode)
    start_decoding(p);
  
  hookdata = (hookdata_t *)safe_alloc(sizeof(hookdata_t));
  hookdata->type = HOOKDATA_PACKET;
  hookdata->data = (void *)p;
  
  /* Raise event */
  hook_event(HOOK_RECEIVED, hookdata);
  
  free(hookdata);
  
  /* If MiTM is active, do packet forwarding */
  if(gbls->mitm_state == MITM_STATE_START)
    packet_forward(p);
  
  packet_free(p);
}

int main(int argc, char **argv)
{
  char errbuf[PCAP_ERRBUF_SIZE];

  atexit(&cleanup);

  globals_init();

  /* Register signals */
  signal(SIGINT, &signal_handler_cb);
  signal(SIGTERM, &signal_handler_cb);
  
  parse_options(argc, argv);
  
  threads_manager_init();
  load_iface_info();
  protos_init();
  ouidb_load();

  /* Get iface name */
  if ((gbls->iface == NULL) && ((gbls->iface = pcap_lookupdev(errbuf)) == NULL)) {
    fatal(__func__, errbuf);
    exit(-1);
  }

  /* Initialize pcap handler */
  pcap = pcap_init(gbls->iface, gbls->snaplen, gbls->promisc, gbls->rfmon, 
		   gbls->cap_timeout);

  /* Get the device type */
  gbls->dlt = pcap_datalink(pcap);

  inject_initialize();

  /* Build the list with all hosts present in the same network */
  if(gbls->scan)
    build_hosts_list(pcap);
  
  /* TODO: possibility to read the hosts from a file */
  
  /* Start MiTM attack if required */
  mitm_start();

  if(gbls->mitm_state == MITM_STATE_START)
    packet_forward_module_init();

  message(COLOR_BOLD"%s %s"COLOR_NORMAL" started", PACKAGE_NAME, VERSION);

  /* Start script engine and run the script */
  se_open();

  if (gbls->promisc)
    debug("start sniffing on '%s' in promisc mode, datalink: %s (%s), snaplen %d", 
	  gbls->iface, pcap_datalink_val_to_name(gbls->dlt), 
	  pcap_datalink_val_to_description(gbls->dlt), gbls->snaplen);
  else
    debug("start sniffing on '%s', datalink: %s (%s), snaplen %d", gbls->iface, 
	  pcap_datalink_val_to_name(gbls->dlt), 
	  pcap_datalink_val_to_description(gbls->dlt), gbls->snaplen);

  /* Start sniffing */
  pcap_loop(pcap, 0, &process_packet, NULL);

  cleanup();

  return EXIT_SUCCESS;
}
