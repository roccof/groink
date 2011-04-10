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
#include <pthread.h>
#include <string.h>
#include <unistd.h>

#include "debug.h"
#include "globals.h"
#include "hook.h"
#include "packet.h"
#include "rp_processor.h"
#include "rp_queue.h"
#include "threads.h"
#include "decoder.h"
/* #include "forward.h" */

static void *processor_thread_cb(void *arg)
{
  rawpacket_t *rp = NULL;
  packet_t *p = NULL;
  hookdata_t *hookdata = NULL;

  THREAD_DEFAULT_INIT;
 
  while (1) {
    THREAD_CANCELLATION_POINT;
    
    rp = get_raw_packet();
    
    /* If there aren't packets wait 1000 microseconds */
    if (rp == NULL) {
      usleep(2000);
      continue;
    }

    p = packet_new(rp->data, rp->len);
    PKT_ADD_FLAG(p, PACKET_FLAG_CAPTURED);

    if (gbls->decode)
      start_decoding(p, rp);

    free(rp->data);
    free(rp);
    
    hookdata = (hookdata_t *)safe_alloc(sizeof(hookdata_t));
    hookdata->type = HOOKDATA_PACKET;
    hookdata->data = (void *)p;
    
    /* Raise event */
    hook_event(HOOK_RECEIVED, hookdata);

    free(hookdata);
    
    /* /\* If MiTM is active, do packet forwarding *\/ */
    /* if(gbls->mitm_state == MITM_STATE_START) */
    /* 	packet_forward(p); */
    
    /* packet_free(p); */
  }
  
  /* Never reached */
  return NULL;
}

/* Start the packet processor */
void start_rp_processor()
{
  /* init_packet_forward_module(); */
  thread_new(RP_PROCESSOR_THREAD_NAME, &processor_thread_cb, NULL);
  debug("packet processor started");
}

void stop_rp_processor()
{
  pthread_t thread = 0;

  thread = thread_id_from_name(RP_PROCESSOR_THREAD_NAME);

  if (thread == 0)
    return;

  thread_stop(thread);

  /* destroy_packet_forward_module(); */
  debug("packet processor stopped");
}
