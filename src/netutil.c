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
#include <regex.h>
#include <string.h>
#include <sys/socket.h>

#include "base.h"
#include "debug.h"
#include "list.h"
#include "netutil.h"
/* #include "protocols/ethernet.h" */

/* TODO: IPv6 support */

#define STR_ADDR_LEN 18
#define ETHER_ADDR 1

#define ETHER_ADDR_LEN 6

/* Example: 192.168.0.1 */
#define IP_ADDR_REGEX							\
  "(^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})$)"

/* Example: 192.168.0.1-30 */
#define IP_RANGE_ADDR_REGEX						\
  "(^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.]" \
  "(25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[-](25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})$)"

/* Example: 192.168.0.0/24 --> [rfc 4632] TEST IT!!! */
#define IP_CIDR_ADDR_REGEX						\
  "(^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.]" \
  "(25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[/]([0-32])$)"

/* Example: 00:11:22:33:44:55 */
#define ETHER_ADDR_REGEX "(^[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]:[0-9A-F][0-9A-F]$)"

static const char *octet2hex[] = {
  "00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0a",
  "0b", "0c", "0d", "0e", "0f", "10", "11", "12", "13", "14", "15",
  "16", "17", "18", "19", "1a", "1b", "1c", "1d", "1e", "1f", "20",
  "21", "22", "23", "24", "25", "26", "27", "28", "29", "2a", "2b",
  "2c", "2d", "2e", "2f", "30", "31", "32", "33", "34", "35", "36",
  "37", "38", "39", "3a", "3b", "3c", "3d", "3e", "3f", "40", "41",
  "42", "43", "44", "45", "46", "47", "48", "49", "4a", "4b", "4c",
  "4d", "4e", "4f", "50", "51", "52", "53", "54", "55", "56", "57",
  "58", "59", "5a", "5b", "5c", "5d", "5e", "5f", "60", "61", "62",
  "63", "64", "65", "66", "67", "68", "69", "6a", "6b", "6c", "6d",
  "6e", "6f", "70", "71", "72", "73", "74", "75", "76", "77", "78",
  "79", "7a", "7b", "7c", "7d", "7e", "7f", "80", "81", "82", "83",
  "84", "85", "86", "87", "88", "89", "8a", "8b", "8c", "8d", "8e",
  "8f", "90", "91", "92", "93", "94", "95", "96", "97", "98", "99",
  "9a", "9b", "9c", "9d", "9e", "9f", "a0", "a1", "a2", "a3", "a4",
  "a5", "a6", "a7", "a8", "a9", "aa", "ab", "ac", "ad", "ae", "af",
  "b0", "b1", "b2", "b3", "b4", "b5", "b6", "b7", "b8", "b9", "ba",
  "bb", "bc", "bd", "be", "bf", "c0", "c1", "c2", "c3", "c4", "c5",
  "c6", "c7", "c8", "c9", "ca", "cb", "cc", "cd", "ce", "cf", "d0",
  "d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8", "d9", "da", "db",
  "dc", "dd", "de", "df", "e0", "e1", "e2", "e3", "e4", "e5", "e6",
  "e7", "e8", "e9", "ea", "eb", "ec", "ed", "ee", "ef", "f0", "f1",
  "f2", "f3", "f4", "f5", "f6", "f7", "f8", "f9", "fa", "fb", "fc",
  "fd", "fe", "ff"
};

unsigned char *ether_addr_aton(const char *addr)
{
  char *p;
  long l;
  int i;
  unsigned char *bytes;

  bytes = (unsigned char *)safe_alloc(ETHER_ADDR_LEN);
  
  for (i=0; i<ETHER_ADDR_LEN; i++) {
    l = strtol(addr, &p, 16);
    
    if (p == addr || l < 0 || l > 0xff || (i < (ETHER_ADDR_LEN - 1) && *p != ':'))
      break;
    
    bytes[i] = (unsigned char)l;
    addr = p + 1; // Skip ':'
  }

  if (i == ETHER_ADDR_LEN && *p == '\0') {
    return bytes;
  } else {
    free(bytes);
    return NULL;
  }
}

char *ether_addr_ntoa(const unsigned char *bytes)
{
  const char *x;
  int i;
  char *addr;
  char *p;

  addr = (char *)safe_alloc(STR_ADDR_LEN);
  
  p = addr;

  for (i=0; i<ETHER_ADDR_LEN; i++) {
    for (x=octet2hex[bytes[i]]; (*p = *x)!='\0'; x++, p++);
    *p++ = ':';
  }
  *(p - 1) = '\0';

  return addr;
}

_uint32 ip_addr_aton(const char *addr)
{
  struct in_addr ip_addr;

  if (inet_aton(addr, &ip_addr) == 0)
    bug(__func__, "invalid ip address");

  return ip_addr.s_addr;
}

char *ip_addr_ntoa(const _uint32 bytes)
{
  struct in_addr ip_addr;
  char *addr = NULL;
  char *ret_addr = NULL;

  ip_addr.s_addr = bytes;
  addr = inet_ntoa(ip_addr);

  ret_addr = (char *)safe_alloc(strlen(addr) + 1);
  memcpy(ret_addr, addr, strlen(addr) + 1);

  return ret_addr;
}

char *calculate_cksum(unsigned char *data, unsigned int len)
{
  // TODO
  return NULL;
}

char *addr_stoa(struct sockaddr *addr) // TODO: IPv6
{
  struct sockaddr_in *addr_in = NULL;

  switch(addr->sa_family) {
  case AF_UNSPEC:
  case ETHER_ADDR:
    return ether_addr_ntoa((_uchar *)addr->sa_data);
    
  case AF_INET:
    addr_in = (struct sockaddr_in *)addr;
    return ip_addr_ntoa(addr_in->sin_addr.s_addr);
    
  default:
    return NULL;
  }
}

int is_ip_addr(char *addr)
{
  regex_t regex;

  if (regcomp(&regex, IP_ADDR_REGEX, REG_EXTENDED | REG_NOSUB | REG_ICASE) != 0)
    bug(__func__, "invalid regex");

  if (regexec(&regex, addr, 0, NULL, 0) == 0) {
    regfree(&regex);
    return 1;
  }
  regfree(&regex);
  return 0;
}

int is_ether_addr(char *addr)
{
  regex_t regex;

  if (regcomp(&regex, ETHER_ADDR_REGEX, REG_EXTENDED | REG_NOSUB | REG_ICASE) != 0)
    bug(__func__, "invalid regex");

  if (regexec(&regex, addr, 0, NULL, 0) == 0) {
    regfree(&regex);
    return 1;
  }
  regfree(&regex);
  return 0;
}

void convert_ip_range_addr_notation(char *addr, List *list)
{
  
}

void convert_ip_cidr_addr_notation(char *addr, List *list)
{

}

/* The address has this format: 192.168.0.10-20 */
int is_ip_range_addr_notation(char *addr)
{
  regex_t regex;

  if (regcomp(&regex, IP_RANGE_ADDR_REGEX, REG_EXTENDED | REG_NOSUB | REG_ICASE) != 0)
    bug(__func__, "invalid regex");

  if (regexec(&regex, addr, 0, NULL, 0) == 0) {
    regfree(&regex);
    return 1;
  }
  regfree(&regex);
  return 0;
}

/* The address has this format: 192.168.0.0/24 */
int is_ip_cidr_addr_notation(char *addr)
{
  regex_t regex;

  if (regcomp(&regex, IP_CIDR_ADDR_REGEX, REG_EXTENDED | REG_NOSUB | REG_ICASE) != 0)
    bug(__func__, "invalid regex");

  if (regexec(&regex, addr, 0, NULL, 0) == 0) {
    regfree(&regex);
    return 1;
  }
  regfree(&regex);
  return 0;
}
