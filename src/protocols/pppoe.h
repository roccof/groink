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
#ifndef GROINK_PPPOE_H
#define GROINK_PPPOE_H

/* RFC 2516 - PPPoE HEADER
 * =======================
 *
 *                        1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |  VER  | TYPE  |      CODE     |          SESSION_ID           |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |            LENGTH             |           payload             ~
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */

#include "base.h"

typedef struct _grk_pppoe
{
  _uint8 vt;         /* Version and Type*/
  _uint8 code;       /* Code */
  _uint16 session;   /* Session */
  _uint16 length;    /* Length */
} pppoe_t;

#define PPPOE_VERSION(pppoe) (((pppoe)->vt & 0xf0) >> 4)
#define PPPOE_TYPE(pppoe) ((pppoe)->vt & 0x0f)

#define PPPOE_HDR_LEN 6

/* PPPoE code */
#define PPPOE_CODE_SESSION         0x00
#define PPPOE_CODE_DISCOVER_PADI   0x09
#define PPPOE_CODE_DISCOVER_PADO   0x07
#define PPPOE_CODE_DISCOVER_PADR   0x19
#define PPPOE_CODE_DISCOVER_PADS   0x65
#define PPPOE_CODE_DISCOVER_PADT   0xa7

/* PPPoE Discovery Stage tag type */
#define PPPOE_TAG_TYPE_EOL              0x0000
#define PPPOE_TAG_TYPE_SERV_NAME        0x0101
#define PPPOE_TAG_TYPE_AC_NAME          0x0102
#define PPPOE_TAG_TYPE_HOST_UNIQ        0x0103
#define PPPOE_TAG_TYPE_AC_COOKIE        0x0104
#define PPPOE_TAG_TYPE_VENDOR_SPEC      0x0105
#define PPPOE_TAG_TYPE_REL_SESS_ID      0x0110
#define PPPOE_TAG_TYPE_SERV_NAME_ERR    0x0201
#define PPPOE_TAG_TYPE_AC_SYS_ERR       0x0202
#define PPPOE_TAG_TYPE_GEN_ERR          0x0203

/* PPPoE decoding error */
#define PPPOE_ERR_BAD_VERSION 0x80

void register_pppoe();

#endif /* GROINK_PPPOE_H */
