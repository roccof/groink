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
#ifndef GROINK_INJECT_H
#define GROINK_INJECT_H

#include "packet.h"

void inject(packet_t *p);
void inject_arp_reply(char *eth_src, char *ip_src, char *eth_target, char *ip_target);
void inject_arp_request(char *eth_src, char *ip_src, char *eth_target, char *ip_target);
void inject_arp(char *eth_src, char *eth_dst, _uint16 opcode, char *sha, char *spa, char *tha, char *tpa);

/*
 * TODO:
 *  - inject_ipv4
 *  - inject_ipv6
 *  - inject_tcp
 *  - inject_tcp6
 *  - inject_udp
 *  - inject_udp6
 *  - inject_icmp
 *  - inject_icmpv6
 */

#endif /* GROINK_INJECT_H */
