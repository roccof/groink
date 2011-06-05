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
#include "debug.h"
#include "threads.h"
#include "utlist.h"

struct _grk_thread_elem {
  pthread_t id;                  /* Thread id*/
  char *name;                    /* Thread name */
  thread_cb callback;            /* Thread callback function */
  struct _grk_thread_elem *next;
};

/* List that contain all threads */
static struct _grk_thread_elem *list = NULL;

/* Mutex */
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

/* Thread's attributes */
static pthread_attr_t attr;

static void thread_kill_all();

void threads_manager_init()
{
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
  struct _grk_thread_elem *new = NULL;
  pthread_t id;

  if (pthread_create(&id, &attr, callback, data) != 0) {
    free(new);
    fatal("thread_new","thread '%s' not created!!!", name);
  }

  new = (struct _grk_thread_elem *)safe_alloc(sizeof(struct _grk_thread_elem));
  new->id = id;
  new->name = name;
  new->callback = callback;
  
  MUTEX_LOCK(&mutex);
  LL_APPEND(list, new);
  MUTEX_UNLOCK(&mutex);

  debug("started thread [0x%x] with name '%s'", id, name);

  return id;
}

void thread_register(pthread_t id, char *name)
{
  struct _grk_thread_elem *new = NULL;

  /* Register thread in the list */
  new = (struct _grk_thread_elem *)safe_alloc(sizeof(struct _grk_thread_elem));
  new->id = id;
  new->name = name;
  new->callback = NULL;

  MUTEX_LOCK(&mutex);
  LL_APPEND(list, new);
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
  struct _grk_thread_elem *t = NULL;
  struct _grk_thread_elem *tmp = NULL;
  
  MUTEX_LOCK(&mutex);

  LL_FOREACH_SAFE (list, t, tmp) {
    if (pthread_equal(t->id, id)) {
      debug("thread '%s' terminated", t->name);
      
      LL_DELETE(list, t);
      MUTEX_UNLOCK(&mutex);
      
      free(t);
      
      return;
    }
  }
  MUTEX_UNLOCK(&mutex);
}

pthread_t thread_id_from_name(char *name)
{
  struct _grk_thread_elem *t = NULL;

  MUTEX_LOCK(&mutex);

  LL_FOREACH (list, t) {
    if (strcmp(name, t->name) == 0) {
      pthread_t id = t->id;
      MUTEX_UNLOCK(&mutex);
      return id;
    }
  }
  MUTEX_UNLOCK(&mutex);

  return 0;
}

int thread_is_occupated_name(char *name)
{
  struct _grk_thread_elem *t = NULL;

  MUTEX_LOCK(&mutex);

  LL_FOREACH (list, t) {
    if (strcmp(name, t->name) == 0) {
      MUTEX_UNLOCK(&mutex);
      return 1;
    }
  }
  MUTEX_UNLOCK(&mutex);

  return 0;
}

static void thread_kill_all()
{
  struct _grk_thread_elem *t = NULL;
  struct _grk_thread_elem *tmp = NULL;
  pthread_t self_id = 0;

  self_id = pthread_self();
  
  MUTEX_LOCK(&mutex);

  LL_FOREACH_SAFE (list, t, tmp) {
    /* Skip ourself */
    if (!pthread_equal(t->id, self_id)) {
      pthread_cancel(t->id);
      /* pthread_join(t->id, NULL); */
      /* pthread_detach(t->id); */
      
      debug("thread '%s' destroyed", t->name);
      
      LL_DELETE(list, t);      
      free(t);
    }
  }
  MUTEX_UNLOCK(&mutex);
}

int thread_exec_num()
{
  int size = 0;
  struct _grk_thread_elem *t = NULL;
  
  MUTEX_LOCK(&mutex);
  LL_FOREACH(list, t) {
    size++;
  }
  MUTEX_UNLOCK(&mutex);

  return size;
}
