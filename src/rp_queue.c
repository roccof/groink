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

#include "debug.h"
#include "packet.h"
#include "rp_queue.h"
#include "threads.h"
#include "utlist.h"

struct _grk_rp_elem {
  rawpacket_t *rp;
  struct _grk_rp_elem *next;
};

/* Queue */
static struct _grk_rp_elem *queue = NULL;

/* Mutex */
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void cleanup_rp_queue()
{
  rawpacket_t *rp = NULL;
  struct _grk_rp_elem *curr = NULL, *tmp = NULL;

  MUTEX_LOCK(&mutex);
  LL_FOREACH_SAFE(queue, curr, tmp) {
    LL_DELETE(queue, curr);
    rp = curr->rp;

    free(curr);
    curr = NULL;

    free(rp->data);
    free(rp);
    rp = NULL;
  }
  MUTEX_UNLOCK(&mutex);
  
  debug("cleanup raw packet queue");
}

/* Add a raw packet in the queue */
void add_raw_packet(rawpacket_t *rp)
{
  struct _grk_rp_elem *elem = NULL;

  if (rp == NULL)
    bug(__func__, "invalid raw packet");

  MUTEX_LOCK(&mutex);

  elem = (struct _grk_rp_elem *)safe_alloc(sizeof(struct _grk_rp_elem));
  elem->rp = rp;
  LL_PREPEND(queue, elem);

  MUTEX_UNLOCK(&mutex);
}

/* Get raw packet from the queue */
rawpacket_t *get_raw_packet()
{
  rawpacket_t *rp = NULL;
  struct _grk_rp_elem *elem = NULL;

  MUTEX_LOCK(&mutex);

  /* No raw packets */
  if (queue == NULL) {
    MUTEX_UNLOCK(&mutex);
    return NULL;
  }

  elem = queue;
  LL_DELETE(queue, elem);

  MUTEX_UNLOCK(&mutex);

  rp = elem->rp;
  free(elem);
  elem = NULL;

  return rp;
}
