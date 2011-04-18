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
#include <arpa/inet.h>
#include <string.h>

#include "pppoe.h"
#include "packet.h"
#include "base.h"
#include "protos.h"
#include "protos_name.h"
#include "selib.h"

static int decode_pppoe(packet_t *p, const _uint8 *bytes, size_t len)
{
  int status = DECODE_OK;
  pppoe_t *pppoe = NULL;
  _uint16 hlen = 0;

  if (len < sizeof(pppoe_t))
    goto err;

  pppoe = (pppoe_t *)bytes;
  /* hlen = PPPOE_HDR_LEN; */
  hlen = htons(pppoe->length);

  if (len < hlen)
    goto err;
  
  /* The payload of PPPoe Discovery Stage contains TAGS */
  if (pppoe->code != PPPOE_CODE_SESSION)
    hlen += htons(pppoe->length);

  packet_append_header(p, PROTO_NAME_PPPOE, (void *)pppoe, hlen);

  /* The payload of PPPoe Discovery Stage contains PPP header */
  /* if (pppoe->code == PPPOE_CODE_SESSION) */
  /*   status = call_decoder(PROTO_PPP, p, (bytes + hlen), (len - hlen)); */

  return status;

 err:
  debug("malformed PPPoE header: invalid length");
  return call_decoder(PROTO_NAME_RAW, p, bytes, len);
}

static int l_pppoe_is_discovery(lua_State *L)
{
  header_t *header = NULL;
  pppoe_t *pppoe = NULL;
  
  header = check_header(L, 1);
  pppoe = (pppoe_t *)header->data;

  lua_pushboolean(L, (pppoe->code != PPPOE_CODE_SESSION));

  return 1;
}

static int l_pppoe_is_session(lua_State *L)
{
  header_t *header = NULL;
  pppoe_t *pppoe = NULL;
  
  header = check_header(L, 1);
  pppoe = (pppoe_t *)header->data;

  lua_pushboolean(L, (pppoe->code == PPPOE_CODE_SESSION));

  return 1;
}

static int l_pppoe_version(lua_State *L)
{
  header_t *header = NULL;
  pppoe_t *pppoe = NULL;
  
  header = check_header(L, 1);
  pppoe = (pppoe_t *)header->data;

  lua_pushnumber(L, PPPOE_VERSION(pppoe));

  return 1;
}

static int l_pppoe_type(lua_State *L)
{
  header_t *header = NULL;
  pppoe_t *pppoe = NULL;
  
  header = check_header(L, 1);
  pppoe = (pppoe_t *)header->data;

  lua_pushnumber(L, PPPOE_TYPE(pppoe));

  return 1;
}

static int l_pppoe_code(lua_State *L)
{
  header_t *header = NULL;
  pppoe_t *pppoe = NULL;
  
  header = check_header(L, 1);
  pppoe = (pppoe_t *)header->data;

  lua_pushnumber(L, pppoe->code);

  return 1;
}

static int l_pppoe_session(lua_State *L)
{
  header_t *header = NULL;
  pppoe_t *pppoe = NULL;
  
  header = check_header(L, 1);
  pppoe = (pppoe_t *)header->data;

  lua_pushnumber(L, ntohs(pppoe->session));

  return 1;
}

static int l_pppoe_payload_len(lua_State *L)
{
  header_t *header = NULL;
  pppoe_t *pppoe = NULL;
  
  header = check_header(L, 1);
  pppoe = (pppoe_t *)header->data;

  lua_pushnumber(L, ntohs(pppoe->length));

  return 1;
}

static int l_pppoe_tags(lua_State *L)
{
  header_t *header = NULL;
  pppoe_t *pppoe = NULL;
  
  _uint8 *payload = NULL;
  _uint16 *tag_type = NULL;
  _uint16 *tag_len = NULL;
  _uint8 *tag_value = NULL;
  char *value = NULL;

  int totlen = 0;
  int len = 0;
  
  header = check_header(L, 1);
  pppoe = (pppoe_t *)header->data;

  if (pppoe->code == PPPOE_CODE_SESSION) {
    lua_pushnil(L);
    return 1;
  }

  /* PPPoE Discovery payload length */
  totlen = ntohs(pppoe->length);

  lua_newtable(L);

  payload = (_uint8 *)(pppoe + 1);

  while (totlen > 0) {  
    tag_type = (_uint16 *)payload;
    tag_len =  (_uint16 *)(tag_type + 1);
    
    len = 4 + ntohs(*tag_len);
    
    /* debug("-------------------------------------------"); */
    /* debug("[PPPoED TAG] type: 0x%x ; len: %d", ntohs(*tag_type), ntohs(*tag_len)); */
    
    switch(ntohs(*tag_type)) {
    case PPPOE_TAG_TYPE_EOL:
      goto stop;
      
    case PPPOE_TAG_TYPE_SERV_NAME:
    case PPPOE_TAG_TYPE_AC_NAME:
    case PPPOE_TAG_TYPE_SERV_NAME_ERR:
    case PPPOE_TAG_TYPE_AC_SYS_ERR:
    case PPPOE_TAG_TYPE_GEN_ERR:
      if (ntohs(*tag_len) > 0) {
	tag_value = payload + 4;
	value = fake_unicode(tag_value, ntohs(*tag_len));
	/* debug("[PPPoED TAG] value: %s", value); */
      }
      break;
      
    case PPPOE_TAG_TYPE_HOST_UNIQ:
    case PPPOE_TAG_TYPE_AC_COOKIE:
    case PPPOE_TAG_TYPE_VENDOR_SPEC:
    case PPPOE_TAG_TYPE_REL_SESS_ID:
      if(ntohs(*tag_len) > 0) {
	tag_value = payload + 4;
	value = hex_string(tag_value, ntohs(*tag_len));
	/* debug("[PPPoED TAG] value: %s", value); */
      }
      break;
      
    default:
      if (ntohs(*tag_len) > 0) {
	tag_value = payload + 4;
	value = fake_unicode(tag_value, ntohs(*tag_len));
	/* debug("[PPPoE TAG] value: %s", value); */
      }
      break;
    }

    lua_pushnumber(L, ntohs(*tag_type));
    lua_pushstring(L, value);
    lua_settable(L, -3);
    
    /* Cleanup */
    if (value != NULL) {
      free(value);
      value = NULL;
      tag_value = NULL;
    }
    
    payload += len;
    totlen -= len;
  }
  
 stop:

  /* Make the table read-only */
  se_setro(L);

  return 1;
}

static const struct luaL_reg pppoe_methods[] = {
  {"is_discovery_stage", l_pppoe_is_discovery},
  {"is_session_stage", l_pppoe_is_session},
  {"version", l_pppoe_version},
  {"type", l_pppoe_type},
  {"code", l_pppoe_code},
  {"session", l_pppoe_session},
  {"payload_length", l_pppoe_payload_len},
  {"tags", l_pppoe_tags},
  {NULL, NULL}
};

void register_pppoe()
{
  proto_t *p = (proto_t *)safe_alloc(sizeof(proto_t));
  p->name = PROTO_NAME_PPPOE;
  p->longname = "PPPoE";
  p->layer = L2;
  p->decoder = decode_pppoe;
  p->methods = (luaL_reg *)pppoe_methods;
  
  proto_register_byname(PROTO_NAME_PPPOE, p);
}
