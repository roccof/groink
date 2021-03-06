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
#include "protos.h"
#include "packet.h"
#include "protocols/ethernet.h"
#include "protocols/arp.h"
#include "protocols/pppoe.h"
#include "protocols/raw.h"
#include "protocols/ipv4.h"
#include "protocols/ipv6.h"
#include "protocols/tcp.h"
#include "protocols/udp.h"
#include "protocols/icmp.h"
#include "protocols/icmp6.h"
#include "protocols/http.h"
#include "protocols/ftp.h"
#include "protocols/sll.h"
#include "protocols/ppp.h"
#include "debug.h"
#include "base.h"
#include "hashtable.h"
#include "threads.h"

typedef void(*proto_cb)();

static const proto_cb protos[] = {
  register_ether,
  register_arp,
  register_pppoe,
  register_raw,
  register_ipv4,
  register_tcp,
  register_udp,
  register_icmp,
  register_ipv6,
  register_icmp6,
  register_http,
  register_ftp,
  register_sll,
  register_ppp,
  NULL
};

struct _pname_table {
  char *name;
  proto_t *p;
  UT_hash_handle hh;
};

struct _pport_table {
  int port;
  proto_t *p;
  UT_hash_handle hh;
};

/* Protocols hashtables */
static struct _pname_table *name_ptable = NULL;
static struct _pport_table *port_ptable = NULL;

/* Mutex for hashtable that contains protos by name */
static pthread_mutex_t mutex_ht1 = PTHREAD_MUTEX_INITIALIZER;

/* Mutex for hashtable that contains protos by port */
static pthread_mutex_t mutex_ht2 = PTHREAD_MUTEX_INITIALIZER;

/* Load all suported protocols */
void protos_init()
{
  int i = 0;
  for (i=0; protos[i]!=NULL; i++)
    protos[i]();

  debug("loaded %d protocol%c", i, (i > 1)? 's' : ' ');
}

static void cleanup_protos_name_table()
{
  struct _pname_table *curr = NULL, *tmp = NULL;

  HASH_ITER(hh, name_ptable, curr, tmp) {
    HASH_DEL(name_ptable, curr);
    
    curr->p->refcount--;
    if (curr->p->refcount == 0) {
      free(curr->p);
      curr->p = NULL;
    }

    free(curr);
    curr = NULL;
  }

  name_ptable = NULL;
}

static void cleanup_protos_port_table()
{
  struct _pport_table *curr = NULL, *tmp = NULL;

  HASH_ITER(hh, port_ptable, curr, tmp) {
    HASH_DEL(port_ptable, curr);
    
    curr->p->refcount--;
    if (curr->p->refcount == 0) {
      free(curr->p);
      curr->p = NULL;
    }

    free(curr);
    curr = NULL;
  }
  port_ptable = NULL;
}

void protos_destroy()
{
  cleanup_protos_port_table();
  cleanup_protos_name_table();
  debug("cleanup loaded protocols");
}

void proto_register_byname(char *name, proto_t *p)
{
  struct _pname_table *e = (struct _pname_table *)safe_alloc(sizeof(struct _pname_table));
  e->name = name;
  e->p = p;

  /* Increment refcount of the protocol struct */
  p->refcount++;

  MUTEX_LOCK(&mutex_ht1);
  HASH_ADD_KEYPTR(hh, name_ptable, e->name, strlen(e->name), e);
  MUTEX_UNLOCK(&mutex_ht1);
}

void proto_register_byport(int port, proto_t *p)
{
  struct _pport_table *e = (struct _pport_table *)safe_alloc(sizeof(struct _pport_table));
  e->port = port;
  e->p = p;

  /* Increment refcount of the protocol struct */
  p->refcount++;

  MUTEX_LOCK(&mutex_ht2);
  HASH_ADD_INT(port_ptable, port, e);
  MUTEX_UNLOCK(&mutex_ht2);
}


void proto_unregister_byname(char *name)
{
  /* TODO */
}

void proto_unregister_byport(int port)
{
  /* TODO */
}

proto_t *proto_get_byname(char *name)
{
  struct _pname_table *e = NULL;

  MUTEX_LOCK(&mutex_ht1);
  HASH_FIND_STR(name_ptable, name, e);
  MUTEX_UNLOCK(&mutex_ht1);

  if (e != NULL)
    return e->p;
  return NULL;
}

proto_t *proto_get_byport(int port)
{
  struct _pport_table *e = NULL;

  MUTEX_LOCK(&mutex_ht2);  
  HASH_FIND_INT(port_ptable, &port, e);
  MUTEX_UNLOCK(&mutex_ht2);

  if (e != NULL)
    return e->p;
  return NULL;
}
