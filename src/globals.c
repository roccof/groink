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
#include "host.h"
#include "mitm.h"
#include "script_engine.h"
#include "pcap_util.h"
#include "utlist.h"

void globals_init()
{
  gbls = (struct _grk_globals *)safe_alloc(sizeof(struct _grk_globals));

  /*** Set default values ***/

  gbls->iface = NULL;
  gbls->promisc = 1;
  gbls->rfmon = 0;
  gbls->scan = 1;

  gbls->hosts = NULL;

  gbls->mtu = 0;
  gbls->link_addr = NULL;
  gbls->net_addr = NULL;
  gbls->net6_addrs = NULL;
  gbls->netmask = NULL;
  gbls->netmask6 = NULL;

  gbls->dlt = 0;
  gbls->cap_packets = 0;
  gbls->snaplen = CAP_SNAPLEN;
  gbls->decode = 1;
  gbls->cap_timeout = CAP_TIMEOUT;

  gbls->script = NULL;
  bzero(gbls->script_argv, MAX_SCRIPT_ARGS);
  gbls->script_argc = 0;
  gbls->script_debug_mode = 0;
  gbls->scripts_dir = NULL;

  gbls->mitm = NULL;
  gbls->mitm_state = MITM_STATE_STOP;
  gbls->mitm_options = NULL;
}

void globals_destroy()
{
  struct _grk_ip6_addrs *curr = NULL, *tmp = NULL;

  if (gbls == NULL)
    return;

  free_hosts_list();
  
  if (gbls->link_addr != NULL)
    free(gbls->link_addr);
  
  if (gbls->net_addr != NULL)
    free(gbls->net_addr);

  if (gbls->netmask != NULL)
    free(gbls->netmask);

  /* Free IPv6 addresses */
  LL_FOREACH_SAFE(gbls->net6_addrs, curr, tmp) {
    LL_DELETE(gbls->net6_addrs, curr);

    free(curr->addr);
    free(curr->netmask);
    free(curr);
    curr = NULL;
  }

  if (gbls->netmask6 != NULL)
    free(gbls->netmask6);
  
  if (gbls->mitm != NULL)
    free(gbls->mitm);
  
  if (gbls->script != NULL)
    free(gbls->script);

  if (gbls->scripts_dir != NULL)
    free(gbls->scripts_dir);
  
  free(gbls);
  gbls = NULL;
}
