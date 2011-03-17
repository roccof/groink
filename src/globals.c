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
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "base.h"
#include "debug.h"
#include "globals.h"
/* #include "host.h" */
#include "list.h"
/* #include "mitm.h" */
/* #include "script_engine.h" */
/* #include "capture.h" */

void globals_init()
{
  gbls = (struct globals_t *)safe_alloc(sizeof(struct globals_t));

  /*** Set default values ***/

  gbls->iface = NULL;
  gbls->promisc = 1;
  gbls->rfmon = 0;
  gbls->daemon = 0;
  gbls->scan = 1;

  list_init(&(gbls->hosts));

  gbls->mtu = 0;
  gbls->link_addr = NULL;
  gbls->net_addr = NULL;
  gbls->net6_addr = NULL;
  gbls->netmask = NULL;

  gbls->sockfd = -1;
  gbls->sockfd6 = -1;

  /* gbls->pcap = NULL; */
  /* gbls->dlt = 0; */
  /* gbls->cap_packets = 0; */
  /* gbls->cs = CAP_STATE_NONE; */
  /* gbls->snaplen = CAPTURE_SNAPLEN; */
  /* gbls->decode = 1; */
  /* gbls->cap_timeout = CAPTURE_TIMEOUT; */

  /* gbls->L = NULL; */
  /* gbls->script = NULL; */
  /* bzero(gbls->script_argv, MAX_SCRIPT_ARGS); */
  /* gbls->script_argc = 0; */
  /* gbls->script_debug_mode = 0; */
  /* gbls->scripts_dir = NULL; */

  gbls->mitm = NULL;
  /* gbls->mitm_state = MITM_STATE_STOP; */
  gbls->mitm_options = NULL;
}

void globals_destroy()
{
  if (gbls == NULL)
    return;

  /* list_free(&(gbls->hosts), &remove_host_cb); */
  
  if (gbls->link_addr != NULL)
    free(gbls->link_addr);
  
  if (gbls->net_addr != NULL)
    free(gbls->net_addr);
  
  if (gbls->netmask != NULL)
    free(gbls->netmask);
  
  if (gbls->mitm != NULL)
    free(gbls->mitm);
  
  if (gbls->script != NULL)
    free(gbls->script);
  
  free(gbls);
  gbls = NULL;
}
