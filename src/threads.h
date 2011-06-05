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
#ifndef GROINK_THREADS_H
#define GROINK_THREADS_H

#include "pthread.h"

#define THREAD_EXIT(status)			\
  thread_unregister(pthread_self());		\
  pthread_exit(status);				\

/* Mutex utility */
#define MUTEX_LOCK(mutex) do{ pthread_mutex_lock(mutex); } while(0)
#define MUTEX_UNLOCK(mutex) do{ pthread_mutex_unlock(mutex); } while(0)

/* Read/Write lock utility */
#define R_LOCK(lock) do{ pthread_rwlock_rdlock(lock); }while(0)
#define W_LOCK(lock) do{ pthread_rwlock_wrlock(lock); }while(0)
#define RW_UNLOCK(lock) do{ pthread_rwlock_unlock(lock); }while(0)

/* Thread cancellable utility */
#define THREAD_SET_CANCELLABLE pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL)
#define THREAD_SET_UNCANCELLABLE pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL)
#define THREAD_SET_CANCEL_TYPE_ASYNC pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL)
#define THREAD_SET_CANCEL_TYPE_DEFERRED pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL)
#define THREAD_CANCELLATION_POINT pthread_testcancel();

#define THREAD_SELF pthread_self()

#define THREAD_DEFAULT_INIT			\
  THREAD_SET_CANCELLABLE;			\
  THREAD_SET_CANCEL_TYPE_DEFERRED;

typedef void *(*thread_cb)(void *data);

void threads_manager_init();
void threads_manager_destroy();
pthread_t thread_new(char *name, thread_cb callback, void *data);
void thread_register(pthread_t id, char *name);
void thread_stop(pthread_t id);
void thread_unregister(pthread_t id);
pthread_t thread_id_from_name(char *name);
int thread_is_occupated_name(char *name);
int thread_exec_num();

#endif /* GROINK_THREADS_H */
