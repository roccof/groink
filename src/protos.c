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
#include "protocols/ethernet.h"
#include "debug.h"
#include "base.h"
#include "hashtable.h"

typedef void(*proto_cb)();

static const proto_cb protos[] = {
  register_ether,
  NULL
};

/* Protocols hashtable */
static Protocol *protos_table = NULL;

/* Load all suported protocols */
void protos_init()
{
  int i = 0;
  for (i=0; protos[i]!=NULL; i++)
    protos[i]();

  debug("loaded %d protocol%c", i, (i > 1)? 's' : ' ');
}

void protos_destroy()
{
  Protocol *curr = NULL, *tmp = NULL;

  HASH_ITER(hh, protos_table, curr, tmp) {
    HASH_DEL(protos_table, curr);
    free(curr);
    curr = NULL;
  }
  HASH_CLEAR(hh, protos_table);
}

Protocol *proto_register(char *name)
{
  Protocol *p = (Protocol *)safe_alloc(sizeof(Protocol));
  p->name = name;
  HASH_ADD_KEYPTR(hh, protos_table, p->name, strlen(p->name), p);
  return p;
}

void proto_unregister(char *name)
{
  Protocol *p = NULL;
  HASH_DEL(protos_table, p);
  free(p);
}

Protocol *proto_get(char *name)
{
  Protocol *p = NULL;
  HASH_FIND_STR(protos_table, name, p);
  return p;
}
