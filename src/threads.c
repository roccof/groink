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
#include <pthread.h>

#include "base.h"
#include "globals.h"
#include "debug.h"
#include "list.h"
#include "threads.h"

struct _thread_elem {
  pthread_t id;          /* Thread id*/
  char *name;            /* Thread name */
  thread_cb callback;    /* Thread callback function */
};

/* List that contain all threads */
static List list;

/* Mutex */
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

/* Thread's attributes */
static pthread_attr_t attr;

void threads_manager_init()
{
  list_init(&list);

  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

  debug("thread manager initialized");
}

void threads_manager_destroy()
{
  thread_kill_all();

  pthread_mutex_destroy(&mutex);
  pthread_attr_destroy(&attr);
}

pthread_t thread_new(char *name, thread_cb callback, void *data)
{
  struct _thread_elem *new = NULL;
  pthread_t id;

  if (pthread_create(&id, &attr, callback, data) != 0) {
    free(new);
    fatal("thread_new","thread '%s' not created!!!", name);
  }

  new = (struct _thread_elem *)safe_alloc(sizeof(struct _thread_elem));
  new->id = id;
  new->name = name;
  new->callback = callback;
  
  MUTEX_LOCK(&mutex);
  list_add_element(&list, new);
  MUTEX_UNLOCK(&mutex);

  debug("started thread [0x%x] with name '%s'", id, name);

  return id;
}

void thread_register(pthread_t id, char *name)
{
  struct _thread_elem *new = NULL;

  // Register thread in the list
  new = (struct _thread_elem *)safe_alloc(sizeof(struct _thread_elem));
  new->id = id;
  new->name = name;
  new->callback = NULL;

  MUTEX_LOCK(&mutex);
  list_add_element(&list, new);
  MUTEX_UNLOCK(&mutex);

  debug("register thread [0x%x] with name '%s'", id, name);
}

void thread_stop(pthread_t id)
{
  pthread_cancel(id);
  pthread_join(id, NULL);
  
  thread_unregister(id);
}

void thread_unregister(pthread_t id)
{
  Element *curr = NULL;
  struct _thread_elem *t = NULL;
  
  MUTEX_LOCK(&mutex);
  
  curr = list.head;
  while (list_has_next(curr)) {
    t = (struct _thread_elem *)list_elem_content(curr);
    
    if (t == NULL) {
      MUTEX_UNLOCK(&mutex);
      bug(__func__, "list element content is NULL");
    }
    
    if (pthread_equal(t->id, id)) {
      debug("thread '%s' terminated", t->name);
      
      list_del_element(&list, curr);
      MUTEX_UNLOCK(&mutex);
      
      free(t);
      
      return;
    }
    curr = list_next(curr);
  }

  MUTEX_UNLOCK(&mutex);
}

pthread_t thread_id_from_name(char *name)
{
  Element *curr;
  struct _thread_elem *t;

  MUTEX_LOCK(&mutex);

  LIST_FOREACH(curr, &list) {
    t = (struct _thread_elem *)list_elem_content(curr);
    
    if (t == NULL) {
      MUTEX_UNLOCK(&mutex);
      bug(__func__, "list element content is NULL");
    }

    if (strcmp(name, t->name) == 0) {
      MUTEX_UNLOCK(&mutex);
      return t->id;
    }
  }
  MUTEX_UNLOCK(&mutex);

  return 0;
}

int thread_is_occupated_name(char *name)
{
  Element *curr;
  struct _thread_elem *t;

  MUTEX_LOCK(&mutex);

  LIST_FOREACH(curr, &list) {
    t = (struct _thread_elem *)list_elem_content(curr);

    if (t == NULL) {
      MUTEX_UNLOCK(&mutex);
      bug(__func__, "list element content is NULL");
    }
    
    if (strcmp(name, t->name) == 0) {
      MUTEX_UNLOCK(&mutex);
      return 1;
    }
  }
  MUTEX_UNLOCK(&mutex);

  return 0;
}

void thread_kill_all()
{
  Element *curr = NULL;
  Element *del = NULL;
  struct _thread_elem *t = NULL;
  pthread_t self_id = 0;

  self_id = pthread_self();
  
  MUTEX_LOCK(&mutex);

  curr = list.head;
  while (list_has_next(curr)) {
    t = (struct _thread_elem *)list_elem_content(curr);

    if (t == NULL) {
      MUTEX_UNLOCK(&mutex);
      bug(__func__, "list element content is NULL");
    }
    
    // Skip ourself
    if(!pthread_equal(t->id, self_id)) {
      del = curr;
      
      pthread_cancel(t->id);
      /* pthread_join(t->id, NULL); */
      /* pthread_detach(t->id); */
      
      debug("thread '%s' destroyed", t->name);
      
      curr = list_next(curr);
      list_del_element(&list, del);
      
      free(t);

      continue;
    }
    curr = list_next(curr);
  }
  MUTEX_UNLOCK(&mutex);
}

int thread_exec_num()
{
  int size;
  
  MUTEX_LOCK(&mutex);
  size = list.size;
  MUTEX_UNLOCK(&mutex);

  return size;
}
