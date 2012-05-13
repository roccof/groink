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
#ifndef GROINK_PPP_H
#define GROINK_PPP_H

#define PPP_HDR_LEN 4

#define PPP_PROTO_IP 0x0021      /* Internet Protocol */
#define PPP_PROTO_IPV6 0x0057    /* Internet Protocol Version 6*/
#define PPP_PROTO_CHAP 0xc223    /* Cryptographic Handshake Auth. Protocol */
#define PPP_PROTO_PAP 0xc023     /* Password Authentication Protocol */
#define PPP_PROTO_LCP 0xc021     /* Link Control Protocol */
#define PPP_PROTO_ECP 0x8053
#define PPP_PROTO_CCP 0x80fd     /* Compression Control Protocol */
#define PPP_PROTO_IPCP 0x8021    /* IP Control Protocol */
#define PPP_PROTO_IPV6CP 0x8057  /* IPv6 Control Protocol */

typedef struct _grk_ppp {
  _uint8 flag;
  _uint8 addr;
  _uint8 control;
  _uint16 proto;
} ppp_t;

typedef struct _grk_lcp_ppp {
  _uint8 code;
  _uint8 id;
  _uint16 len;
} ppp_lcp_t;

void register_ppp();

#endif /* GROINK_PPP_H */
