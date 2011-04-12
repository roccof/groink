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
#include <lualib.h>
#include <lauxlib.h>
#include <string.h>

#include "selib.h"
#include "packet.h"
#include "protos.h"
#include "debug.h"
#include "utlist.h"

static packet_t *check_packet(lua_State *L, int arg)
{
   return (packet_t *)check_object(L, arg, SE_OBJ_TYPE_PACKET, SE_OBJ_NAME_PACKET);
}

static int l_packet_headers(lua_State *L)
{
  header_t *h = NULL;
  int i = 1;
  packet_t *p = check_packet(L, -1);

  lua_newtable(L);

  DL_FOREACH (p->headers, h) {
    lua_pushnumber(L, i);

    lua_newtable(L);

    lua_pushstring(L, h->proto);
    se_pushobject(L, h, SE_OBJ_TYPE_HEADER, SE_OBJ_NAME_HEADER);
    lua_settable(L, -3);

    se_setro(L); /* Read-Only table */

    lua_settable(L, -3);
  }

  se_setro(L); /* Read-Only table */

  return 1;
}

static int l_packet_num_headers(lua_State *L)
{
  packet_t *p = check_packet(L, -1);
  lua_pushnumber(L, p->num_headers);
  return 1;
}

static int l_packet_get_header(lua_State *L)
{
  header_t *h = NULL;
  packet_t *p = NULL;
  char *proto = NULL;

  proto = (char *)luaL_checkstring(L, -1);
  p = check_packet(L, -2);

  h = packet_get_header(p, proto);
  
  if (h == NULL)
    lua_pushnil(L);
  else
    se_pushobject(L, h, SE_OBJ_TYPE_HEADER, SE_OBJ_NAME_HEADER);

  return 1;
}

static int l_packet_contains(lua_State *L)
{
  packet_t *p = NULL;
  char *proto = NULL;

  proto = (char *)luaL_checkstring(L, -1);
  p = check_packet(L, -2);

  lua_pushboolean(L, packet_contains_header(p, proto));
  return 1;
}

static int l_packet_data(lua_State *L)
{
  packet_t *p = check_packet(L, -1);
  lua_pushlstring(L, (const char *)p->data, p->len);
  return 1;
}

static int l_packet_len(lua_State *L)
{
  packet_t *p = check_packet(L, -1);
  lua_pushnumber(L, p->len);
  return 1;
}

static int l_packet_src_hwaddr(lua_State *L)
{
  packet_t *p = check_packet(L, -1);
  lua_pushstring(L, p->hw_srcaddr);
  return 1;
}

static int l_packet_dst_hwaddr(lua_State *L)
{
  packet_t *p = check_packet(L, -1);
  lua_pushstring(L, p->hw_dstaddr);
  return 1;
}

static int l_packet_dst_netaddr(lua_State *L)
{
  packet_t *p = check_packet(L, -1);
  lua_pushstring(L, p->net_dstaddr);
  return 1;
}

static int l_packet_src_netaddr(lua_State *L)
{
  packet_t *p = check_packet(L, -1);
  lua_pushstring(L, p->net_srcaddr);
  return 1;
}

static int l_packet_setdrop(lua_State *L)
{
  packet_t *p = NULL;
  int drop = 0;

  p = check_packet(L, 1);
  luaL_checktype(L, 2, LUA_TBOOLEAN);
  drop = lua_toboolean(L, -1);

  if(drop)
    PKT_ADD_FLAG(p, PACKET_FLAG_DROP);
  else
    PKT_REMOVE_FLAG(p, PACKET_FLAG_DROP);

  return 0;
}

static int l_packet_isdrop(lua_State *L)
{
  packet_t *p = check_packet(L, 1);
  lua_pushboolean(L, PKT_HAS_FLAG(p, PACKET_FLAG_DROP));
  return 1;
}

static int l_packet_setunmod(lua_State *L)
{
  packet_t *p = NULL;
  int mod = 0;

  p = check_packet(L, 1);
  luaL_checktype(L, 2, LUA_TBOOLEAN);
  mod = lua_toboolean(L, -1);
  
  if(mod)
    PKT_ADD_FLAG(p, PACKET_FLAG_UNMODIFICABLE);
  else
    PKT_REMOVE_FLAG(p, PACKET_FLAG_UNMODIFICABLE);

  return 0;
}

static int l_packet_isunmod(lua_State *L)
{
  packet_t *p = check_packet(L, 1);
  lua_pushboolean(L, PKT_HAS_FLAG(p, PACKET_FLAG_UNMODIFICABLE));
  return 1;
}

static int l_packet_tostring(lua_State *L)
{
  lua_pushfstring(L, "Packet: %p", lua_touserdata(L, -1));
  return 1;
}

static int l_packet_gc(lua_State *L)
{
  packet_t *p = check_packet(L, -1);
  packet_free(p);
  return 0;
}

static int l_packet_eq(lua_State *L)
{
  packet_t *p1 = check_packet(L, -1);
  packet_t *p2 = check_packet(L, -2);

  if (p2->len != p1->len)
    lua_pushboolean(L, 0);

  if (memcmp(p2->data, p1->data, p2->len) != 0)
    lua_pushboolean(L, 0);

  lua_pushboolean(L, 1);

  return 1;
}

static const struct luaL_reg packet_methods[] = {
  {"headers", l_packet_headers},
  {"num_headers", l_packet_num_headers},
  {"get_header", l_packet_get_header},
  {"len", l_packet_len},
  {"data", l_packet_data},
  /* {"is_ip_packet", l_packet_isip}, */
  /* {"is_tcp_packet", l_packet_istcp}, */
  /* {"is_udp_packet", l_packet_isudp}, */
  {"contains_header", l_packet_contains},
  {"hw_srcaddr", l_packet_src_hwaddr},
  {"hw_dstaddr", l_packet_dst_hwaddr},
  {"net_srcaddr", l_packet_src_netaddr},
  {"net_dstaddr", l_packet_dst_netaddr},
  {"set_drop", l_packet_setdrop},
  {"is_drop", l_packet_isdrop},
  {"set_unmodificable", l_packet_setunmod},
  {"is_unmodificable", l_packet_isunmod},
  {NULL, NULL}
};

void se_open_packet(lua_State *L)
{
  luaL_newmetatable(L, SE_OBJ_NAME_PACKET);

  lua_pushstring(L, "__index");
  lua_pushvalue(L, -2);
  lua_settable(L, -3); /* metatable.__index = metatable */

  lua_pushstring(L, "__tostring");
  lua_pushcfunction(L, l_packet_tostring);
  lua_settable(L, -3); /* metatable.__tostring = cfunc */

  lua_pushstring(L, "__gc");
  lua_pushcfunction(L, l_packet_gc);
  lua_settable(L, -3); /* metatable.__gc = cfunc */

  lua_pushstring(L, "__eq");
  lua_pushcfunction(L, l_packet_eq);
  lua_settable(L, -3); /* metatable.__eq = cfunc */
  
  /* Setting object methods */
  luaL_register(L, NULL, packet_methods);
}
