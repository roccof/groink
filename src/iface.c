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
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <ifaddrs.h>

#include "base.h"
#include "debug.h"
#include "globals.h"
#include "netutil.h"

void load_iface_info() /* TODO: IPv6 support */
{
  int fd = -1;
  /* int fd6 = -1; */
  struct ifreq ifr;

  if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    fatal("load_iface_info", "error");

/* #ifdef SIOCGIFNETMASK_IN6 */
/*   if ((fd6 = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) */
/*     warning("load_iface_info", "error6"); */
/* #endif */

  strncpy(ifr.ifr_name, gbls->iface, sizeof(ifr.ifr_name));

  // Get iface mtu
  if (ioctl(fd, SIOCGIFMTU, &ifr) < 0) {
    warning("MTU, assuming 1500");
    gbls->mtu = 1500;
  } else {
    gbls->mtu = ifr.ifr_mtu;
    debug("MTU: %d", gbls->mtu);
  }

  /* Get hardware address */
  if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
    warning("the iface %s has no mac address associated", gbls->iface);
  } else {
    gbls->link_addr = addr_stoa(&(ifr.ifr_hwaddr));
    if (gbls->link_addr == NULL)
      warning("the iface %s has no mac address associated", gbls->iface);
    else
      debug("HW ADDR: %s", gbls->link_addr);
  }

  /* Get network address */
  if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
    warning("the iface %s has no ip address associated", gbls->iface);
  } else {
    gbls->net_addr = addr_stoa(&(ifr.ifr_addr));
    if (gbls->net_addr == NULL)
      warning("the iface %s has no ip address associated", gbls->iface);
    else
      debug("IP ADDR: %s", gbls->net_addr);
  }

  /* Get netmask */
  if (ioctl(fd, SIOCGIFNETMASK, &ifr) < 0) {
    warning("the iface %s has no netmask of ip address associated", gbls->iface);
  } else {
    gbls->netmask = addr_stoa(&(ifr.ifr_netmask));
    if (gbls->netmask == NULL)
      warning("the iface %s has no netmask of ip address associated", gbls->iface);
    else
      debug("NETMASK: %s", gbls->netmask);
  }
  
  if(fd > 0)
    close(fd);
  
  /* if(fd6 > 0) */
  /*   close(fd6); */
}
