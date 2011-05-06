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
#include <lua.h>
#include <arpa/inet.h>

#include "base.h"
#include "packet.h"
#include "ipv6.h"
#include "ipv4.h"
#include "protos.h"
#include "protos_name.h"
#include "netutil.h"
#include "selib.h"

static int decode_ipv6(packet_t *p, const _uint8 *bytes, size_t len)
{
  return DECODE_OK;
}

static const struct luaL_reg ip6_methods[] = {
  {NULL, NULL}
};

void register_ipv6()
{
  proto_t *p = (proto_t *)safe_alloc(sizeof(proto_t));
  p->name = PROTO_NAME_IPV6;
  p->longname = "Internet Protocol version 6";
  p->layer = L3;
  p->decoder = decode_ipv6;
  p->methods = (luaL_reg *)ip6_methods;
  
  proto_register_byname(PROTO_NAME_IPV6, p);
}
