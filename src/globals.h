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
#ifndef GROINK_GLOBALS_H
#define GROINK_GLOBALS_H

#include "mitm.h"
#include "script_engine.h"
#include "host.h"
#include "netutil.h"

struct _grk_globals {

  char *iface;                            /* Network interface */
  int promisc;                            /* Promisc mode */
  int rfmon;                              /* Monitor mode */
  int scan;                               /* Host scanning */

  host_t *hosts;                          /* List of all hosts present 
					     in the same network */

  int mtu;                                /* Maximum transfer unit */
  char *link_addr;                        /* Hardware address */
  char *net_addr;                         /* Network IPv4 address */
  struct _grk_ip6_addrs *net6_addrs;      /* Network IPv6 addresses */
  char *netmask;                          /* IPv4 network mask */
  char *netmask6;                         /* IPv6 network mask */

  int dlt;                                /* Data link type  */
  long cap_packets;                       /* Captured packet counter */
  int snaplen;                            /* Captured packet length */
  int decode;                             /* If 1 the packet is decoded */
  int cap_timeout;                        /* Pcap capture packet timeout*/

  char *script;                           /* Script to run */
  char *script_argv[MAX_SCRIPT_ARGS];     /* Arguments of script */
  int script_argc;                        /* Number of argument of script */
  int script_debug_mode;                  /* Script debug mode */
  char *selib_dir;                        /* Selib directory */
  char *scripts_dir;                      /* Scripts directory */

  char *mitm;                             /* MiTM attack name */
  mitm_state_t mitm_state;                /* MiTM state */
  char *mitm_options;
};

struct _grk_globals *gbls;

void globals_init();
void globals_destroy();

#endif /* GROINK_GLOBALS_H */
