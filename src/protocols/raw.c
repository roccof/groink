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
#include "base.h"
#include "packet.h"
#include "raw.h"
#include "protos.h"
#include "protos_name.h"

static int decode_raw(packet_t *p, const _uint8 *bytes, size_t len)
{
  packet_append_header(p, PROTO_NAME_RAW, (void *)bytes, len);
  return DECODE_OK;
}

void register_raw()
{
  proto_t *p = (proto_t *)safe_alloc(sizeof(proto_t));
  p->name = PROTO_NAME_RAW;
  p->longname = "Raw Header";
  p->layer = L5;
  p->decoder = decode_raw;
  p->dissect = NULL;
  
  proto_register_byname(PROTO_NAME_RAW, p);
}
