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

#include "hook.h"
#include "debug.h"
#include "base.h"
#include "threads.h"
#include "utlist.h"

/* Mutex */
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

/* Hook list element */
struct _grk_hook_elem {
  hookevent_t event;            /* Hook event */
  hook_cb_t callback;           /* Callback function */
  struct _grk_hook_elem *next;
};

static struct _grk_hook_elem *list = NULL;

void hook_cleanup()
{
  struct _grk_hook_elem *curr = NULL, *tmp = NULL;

  MUTEX_LOCK(&mutex);

  LL_FOREACH_SAFE (list, curr, tmp) {
    LL_DELETE(list, curr);
    free(curr);
    curr = NULL;
  }
  MUTEX_UNLOCK(&mutex);

  debug("cleanup hook module");
}

void hook_register(hookevent_t event, hook_cb_t callback)
{
  struct _grk_hook_elem *hook = (struct _grk_hook_elem *)
    safe_alloc(sizeof(struct _grk_hook_elem));
  hook->event = event;
  hook->callback = callback;

  MUTEX_LOCK(&mutex);
  LL_APPEND(list, hook);
  MUTEX_UNLOCK(&mutex);

  debug("hook registered");
}

void hook_unregister(hookevent_t event, hook_cb_t callback)
{
  struct _grk_hook_elem *curr = NULL, *tmp = NULL;

  MUTEX_LOCK(&mutex);

  LL_FOREACH_SAFE (list, curr, tmp) {
    if (curr->event == event && curr->callback == callback) {
      LL_DELETE(list, curr);
      
      MUTEX_UNLOCK(&mutex);
      
      free(curr);
      curr = NULL;
      
      debug("hook unregistered");
      return;
    }
  }
  MUTEX_UNLOCK(&mutex);
}

void hook_event(hookevent_t event, hookdata_t *data)
{
  struct _grk_hook_elem *hook = NULL;

  if (data == NULL)
    bug(__func__, "invalid hook data");

  MUTEX_LOCK(&mutex);

  LL_FOREACH (list, hook) {
    if (hook->event == event && hook->callback != NULL) {
      MUTEX_UNLOCK(&mutex);
      hook->callback(data);
      MUTEX_LOCK(&mutex);
    }
  }
  MUTEX_UNLOCK(&mutex);
}
