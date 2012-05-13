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
#include "ppp.h"
#include "selib.h"

static int decode_ppp(packet_t *p, const _uint8 *bytes, size_t len)
{
  ppp_t *ppp = (ppp_t *)bytes;
  packet_append_header(p, PROTO_NAME_PPP, (void *)ppp, 0);

  debug("PPP:");
  debug("\t- FLAG: %d", (int)ppp->flag);
  debug("\t- ADDR: %d", (int)ppp->addr);
  debug("\t- CONTROL: %d", (int)ppp->control);
  debug("\t- PROTO: %d", (int)ppp->proto);
  debug("--------------------------------------------");

  return DECODE_OK;
}

static int l_dissect_ppp(lua_State *L)
{
  header_t *h = NULL;

  h = check_header(L, 1);

  lua_newtable(L);

  /* lua_pushstring(L, "pkt_type"); */
  /* lua_pushnumber(L, ntohs(sll->type)); */
  /* lua_settable(L, -3); */

  se_setro(L);

  return 1;
}

void register_ppp()
{
  proto_t *p = (proto_t *)safe_alloc(sizeof(proto_t));
  p->name = PROTO_NAME_PPP;
  p->longname = "Point To Point Protocol";
  p->layer = L3;
  p->decoder = decode_ppp;
  p->dissect = l_dissect_ppp;
  
  proto_register_byname(PROTO_NAME_PPP, p);
}
