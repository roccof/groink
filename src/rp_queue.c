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
#include "list.h"
#include "packet.h"
#include "rp_queue.h"
#include "threads.h"

/* Queue */
static List queue; /* TODO: real queue */

static int _rpq_init = 0;

/* Mutex */
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void init_rp_queue()
{
  if (_rpq_init == 1)
    return;

  list_init(&queue);

  _rpq_init = 1;

  debug("raw packet queue initialized");
}

void destroy_rp_queue()
{
  Element *curr, *del;
  RawPacket *rp;

  if (_rpq_init == 0)
    return;

  _rpq_init = 0;
  
  MUTEX_LOCK(&mutex);

  curr = queue.head;
  while (list_has_next(curr)) {
    rp = (RawPacket *)list_elem_content(curr);
    
    if (rp == NULL) {
      MUTEX_UNLOCK(&mutex);
      bug(__func__,"list element content is NULL");
    }
    
    del = curr;
    curr = list_next(curr);
    list_del_element(&queue, del);
    
    free(rp->data);
    free(rp);
    rp = NULL;
  }
  MUTEX_UNLOCK(&mutex);
  
  debug("raw packet queue destroyed");
}

/* Add a raw packet in the queue */
void add_raw_packet(RawPacket *rp)
{
  if (rp == NULL)
    bug(__func__, "invalid raw packet");

  MUTEX_LOCK(&mutex);
  list_add_element(&queue, rp);
  MUTEX_UNLOCK(&mutex);
}

/* Get raw packet from the queue */
RawPacket *get_raw_packet()
{
  RawPacket *rp = NULL;

  MUTEX_LOCK(&mutex);

  /* No raw packet */
  if (queue.head == NULL) {
    MUTEX_UNLOCK(&mutex);
    return NULL;
  }

  rp = (RawPacket *)list_elem_content(queue.head);
  list_del_element(&queue, queue.head);

  MUTEX_UNLOCK(&mutex);

  return rp;
}

int rp_queue_size()
{
  int size;

  MUTEX_LOCK(&mutex);
  size = queue.size;
  MUTEX_UNLOCK(&mutex);

  return size;
}
