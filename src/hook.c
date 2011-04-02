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
#include "list.h"
#include "debug.h"
#include "base.h"
#include "threads.h"

static List list;

static int _hook_init = 0;

/* Mutex */
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

/* Hook list element */
struct _grk_hook_elem {
  hookevent_t event;      /* Hook event */
  hook_cb_t callback;     /* Callback function */
};

void hook_init()
{
  if (_hook_init == 1)
    return;

  list_init(&list);

  _hook_init = 1;

  debug("hook module initialized");
}

void hook_destroy()
{
  Element *curr = list.head;
  Element *del = NULL;

  if (_hook_init == 0)
    return;

  _hook_init = 0;

  MUTEX_LOCK(&mutex);

  while (list_has_next(curr)) {
    struct _grk_hook_elem *elem = (struct _grk_hook_elem *)list_elem_content(curr);
    
    if (elem == NULL) {
      MUTEX_UNLOCK(&mutex);
      bug(__func__, "invalid list content element");
    }
    
    del = curr;
    curr = list_next(curr);
    
    list_del_element(&list, del);
    
    free(elem);
    elem = NULL;
  }
  
  MUTEX_UNLOCK(&mutex);
  debug("hook module destroyed");
}

void hook_register(hookevent_t event, hook_cb_t callback)
{
  struct _grk_hook_elem *hook = (struct _grk_hook_elem *)safe_alloc(sizeof(struct _grk_hook_elem));
  hook->event = event;
  hook->callback = callback;

  MUTEX_LOCK(&mutex);
  list_add_element(&list, hook);
  MUTEX_UNLOCK(&mutex);

  debug("hook registered");
}

void hook_unregister(hookevent_t event, hook_cb_t callback)
{
  Element *curr = list.head;

  MUTEX_LOCK(&mutex);

  while (list_has_next(curr)) {
    struct _grk_hook_elem *elem = (struct _grk_hook_elem *)list_elem_content(curr);
    
    if (elem == NULL) {
      MUTEX_UNLOCK(&mutex);
      bug(__func__, "invalid list content element");
    }
    
    if (elem->event == event && elem->callback == callback) {
      list_del_element(&list, curr);
      
      MUTEX_UNLOCK(&mutex);
      
      free(elem);
      elem = NULL;
      
      debug("hook unregistered");
      return;
    }
    
    curr = list_next(curr);
  }
  
  MUTEX_UNLOCK(&mutex);
}

void hook_event(hookevent_t event, hookdata_t *data)
{
  Element *curr = NULL;

  if (data == NULL)
    bug(__func__, "invalid hook data");

  MUTEX_LOCK(&mutex);

  LIST_FOREACH(curr, &list) {
    struct _grk_hook_elem *hook = (struct _grk_hook_elem *)list_elem_content(curr);
    
    if (hook == NULL) {
      MUTEX_UNLOCK(&mutex);
      bug(__func__, "invalid list content element");
    }
    
    if (hook->event == event) {
      MUTEX_UNLOCK(&mutex);
      hook->callback(data);
      MUTEX_LOCK(&mutex);
    }
  }
  
  MUTEX_UNLOCK(&mutex);
}
