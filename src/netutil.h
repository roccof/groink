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
#ifndef GROINK_NETUTIL_H
#define GROINK_NETUTIL_H

#include <netinet/in.h>

#include "base.h"
#include "list.h"

#define ETHER_BROADCAST "ff:ff:ff:ff:ff:ff"

#define ARP_STORM_WAIT 10 /* milliseconds */

unsigned char *ether_addr_aton(const char *addr);
char *ether_addr_ntoa(const unsigned char *bytes);
_uint32 ip_addr_aton(const char *addr);
char *ip_addr_ntoa(const _uint32 bytes);
char *calculate_cksum(unsigned char *data, unsigned int len);
char *addr_stoa(struct sockaddr *addr);
int is_ip_addr(char *addr);
int is_ether_addr(char *addr);
int is_ip_range_addr_notation(char *addr);
void convert_ip_range_addr_notation(char *addr, List *list);
int is_ip_cidr_addr_notation(char *addr);
void convert_ip_cidr_addr_notation(char *addr, List *list);

#endif /* GROINK_NETUTIL_H */
