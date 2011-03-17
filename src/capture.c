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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <pthread.h>

#include "config.h"
#include "base.h"
#include "capture.h"
#include "debug.h"
#include "globals.h"
#include "packet.h"
#include "rp_queue.h"
#include "threads.h"

static void process_packet(u_char *user, const struct pcap_pkthdr *header, const u_char *bytes)
{
  RawPacket *p = NULL;
  unsigned char *data = NULL;

  if (header->len == 0 || bytes == NULL) {
      /*
       * XXX:
       *     If header->len is 0, header->caplen is
       *     greater than zero. Why???? oO
       */
      return;
    }

  /* Skip truncated packet */
  if (header->len > gbls->snaplen) {
    debug("captured truncated packet [pkt-len: %d, snaplen: %d], skipping...",
	  header->len, gbls->snaplen);
    return;
  }

  gbls->cap_packets++;

  /* Copy packet data */
  data = (unsigned char *)safe_alloc(header->len);
  memcpy(data, bytes, header->len);

  /* Alloc raw packet */
  p = (RawPacket *)safe_alloc(sizeof(RawPacket));
  p->data = data;
  p->len = header->len;

  /* Add packet in the queue */
  add_raw_packet(p);
}

static void *capture_thread_cb(void *arg)
{
  THREAD_DEFAULT_INIT;

  pcap_loop(gbls->pcap, 0, &process_packet, NULL);

  return NULL;
}

void start_sniffing()
{
  if (gbls->cs != CAP_STATE_NONE) {
    warning("you can't start sniffing, already started");
    return;
  }

  if (gbls->promisc)
    debug("start sniffing on '%s' in promisc mode, datalink: %s (%s), snaplen %d", gbls->iface, 
	  pcap_datalink_val_to_name(gbls->dlt), pcap_datalink_val_to_description(gbls->dlt), gbls->snaplen);
  else
    debug("start sniffing on '%s', datalink: %s (%s), snaplen %d", gbls->iface, pcap_datalink_val_to_name(gbls->dlt),  
	  pcap_datalink_val_to_description(gbls->dlt), gbls->snaplen);

  gbls->cs = CAP_STATE_STARTED;
  
  thread_new(CAPTURE_THREAD_NAME, &capture_thread_cb, NULL);
}

void stop_sniffing()
{
  pthread_t thread = 0;

  thread = thread_id_from_name(CAPTURE_THREAD_NAME);

  if (thread == 0)
    return;

  thread_stop(thread);

  /* pcap_breakloop(gbls->pcap); */
  
  gbls->cs = CAP_STATE_NONE;
  debug("sniffing stopped");
}

void capture_engine_init()
{
  char errbuf[PCAP_ERRBUF_SIZE];
  int status;

  if ((gbls->iface == NULL) && ((gbls->iface = pcap_lookupdev(errbuf)) == NULL))
    fatal(__func__, errbuf);

#ifdef HAVE_PCAP_CREATE

  gbls->pcap = pcap_create(gbls->iface, errbuf);

  if (gbls->pcap == NULL)
    fatal(__func__, errbuf);

  status = pcap_set_snaplen(gbls->pcap, gbls->snaplen);
  if (status != 0)
    fatal(__func__, "Can't set snapshot length on %s: %s", gbls->iface, pcap_statustostr(status));

  status = pcap_set_promisc(gbls->pcap, gbls->promisc);
  if (status != 0)
    warning("can't set promisc mode for %s: %s", gbls->iface, pcap_statustostr(status));

  status = pcap_set_rfmon(gbls->pcap, gbls->rfmon);
  if (status != 0)
    warning("can't set monitor mode for %s: %s", gbls->iface, pcap_statustostr(status));

  status = pcap_set_timeout(gbls->pcap, gbls->cap_timeout);
  if (status != 0)
    warning("can't set timeout: %s", pcap_statustostr(status));

  status = pcap_activate(gbls->pcap);
  switch(status) {
  case PCAP_ERROR:
    fatal(__func__, "%s", pcap_statustostr(status));
    break;
    
  case PCAP_ERROR_NO_SUCH_DEVICE:
    fatal(__func__, "no such device (%s)", pcap_statustostr(status));
    break;
    
  case PCAP_ERROR_PERM_DENIED:
    fatal(__func__, "permission denied (%s)", pcap_statustostr(status));
    break;
    
  case PCAP_ERROR_IFACE_NOT_UP:
    fatal(__func__, "iface %s not up (%s)", gbls->iface, pcap_statustostr(status));
    break;
    
  case PCAP_ERROR_RFMON_NOTSUP:
    fatal(__func__, "monitor mode not supported for %s (%s)", gbls->iface, pcap_statustostr(status));
    break;
    
  case PCAP_ERROR_ACTIVATED:
    fatal(__func__, "%s", pcap_statustostr(status));
    break;
    
  case PCAP_WARNING:
    warning("%s", pcap_statustostr(status));
    break;
    
  case PCAP_WARNING_PROMISC_NOTSUP:
    warning("promisc mode for %s not supported (%s)", gbls->iface, pcap_statustostr(status));
    break;
  }
  
#else
  
  /* Open the device for capturing */
  gbls->pcap = pcap_open_live(gbls->iface, gbls->snaplen, gbls->promisc, gbls->cap_timeout, errbuf);

  if (gbls->pcap == NULL)
    fatal(__func__, errbuf);

#endif /* HAVE_PCAP_CREATE */
  
  /* Get the device type */
  gbls->dlt = pcap_datalink(gbls->pcap);
  
  /* TODO: control if datalink is supported!!! */

  debug("capture engine initialized");
}

void capture_engine_destroy()
{
  struct pcap_stat ps;

  if (gbls->pcap == NULL)
    return;

  if (gbls->cs == CAP_STATE_STARTED)
    stop_sniffing();
  
  if (pcap_stats(gbls->pcap, &ps) == -1)
    fatal(__func__, pcap_geterr(gbls->pcap));

  debug("cap/recv/drop packet: %d/%d/%d", gbls->cap_packets, ps.ps_recv, ps.ps_drop);

  pcap_close(gbls->pcap);

  debug("capture engine closed");
}
