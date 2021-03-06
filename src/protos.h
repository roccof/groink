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
#ifndef GROINK_PROTOS_H
#define GROINK_PROTOS_H

#include <lua.h>
#include <lauxlib.h>

#include "hashtable.h"
#include "decoder.h"

typedef enum _grk_layer {
  L2,
  L3,
  L4,
  L5
} layer_t;

typedef struct _grk_protocol {
  char *name;                /* Short protocol name */
  char *longname;            /* Long protocol name */
  layer_t layer;             /* Protocol layer */
  lua_CFunction dissect;     /* Lua callback function for dissecting header data */
  decoder_cb_t decoder;      /* Protocol decoder callback */
  int refcount;              /* Used from hashtables, it indicates if the struct 
				can be freed */
} proto_t;

void protos_init();
void protos_destroy();
void proto_register_byname(char *name, proto_t *p);
void proto_register_byport(int port, proto_t *p);
void proto_unregister_byname(char *name);
void proto_unregister_byport(int port);
proto_t *proto_get_byname(char *name);
proto_t *proto_get_byport(int port);

#endif /* GROINK_PROTOS_H */
