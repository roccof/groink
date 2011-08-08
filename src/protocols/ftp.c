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
#include "protos_name.h"
#include "protos.h"
#include "ftp.h"

static int decode_ftp(packet_t *p, const _uint8 *bytes, size_t len)
{
  packet_set_payload(p, PROTO_NAME_FTP, (void *)bytes, len);
  return DECODE_OK;
}

void register_ftp()
{
  proto_t *p = (proto_t *)safe_alloc(sizeof(proto_t));
  p->name = PROTO_NAME_FTP;
  p->longname = "File Transfer Protocol";
  p->layer = L5;
  p->decoder = decode_ftp;
  p->methods = NULL;
  
  proto_register_byname(PROTO_NAME_FTP, p);
  proto_register_byport(21, p);
}
