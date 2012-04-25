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
#ifndef GROINK_SLL_H
#define GROINK_SLL_H

/*
 * Linux "cooked" capture encapsulation:
 * +---------------------------+
 * |        Packet type        |
 * |        (2 Octets)         |
 * +---------------------------+
 * |       ARPHRD_ type        |
 * |        (2 Octets)         |
 * +---------------------------+
 * | Link-layer address length |
 * |         (2 Octets)        |
 * +---------------------------+
 * |    Link-layer address     |
 * |         (8 Octets)        |
 * +---------------------------+
 * |        Protocol type      |
 * |         (2 Octets)        |
 * +---------------------------+
 * |         Payload           |
 * .                           .
 * .                           .
 * .                           .
 *
 * More info: http://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html
 *
 */

typedef struct _grk_sll {
  _uint16 type;       /* Packet type */
  _uint16 arp_hdr;    /* ARPHDR_ type */
  _uint16 addr_len;   /* Link-layer address length */
  char addr[8];       /* Link-layer address */
  _uint16 proto;      /* Protocol type */
} sll_t;

#define SLL_HDR_LEN 12

void register_sll();

#endif
