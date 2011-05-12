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

#include "debug.h"
#include "globals.h"
#include "netutil.h"

void load_iface_info()
{
  int fd = -1;
  struct ifreq ifr;
  struct ifaddrs *ifaddr = NULL, *ifa = NULL;

  /* IPv4 socket */
  if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    fatal(__func__, "unable to get iface %s info", gbls->iface);

  if (getifaddrs(&ifaddr) == -1) {
    close(fd);
    fatal(__func__, "unable to get iface %s info", gbls->iface);
  }

  strncpy(ifr.ifr_name, gbls->iface, sizeof(ifr.ifr_name));

  /* MTU */
  if (ioctl(fd, SIOCGIFMTU, &ifr) < 0) {
    warning("MTU, assuming 1500");
    gbls->mtu = 1500;
  } else {
    gbls->mtu = ifr.ifr_mtu;
    debug("MTU: %d", gbls->mtu);
  }

  /* Hardware address */
  if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
    warning("the iface %s has no mac address associated", gbls->iface);
  } else {
    gbls->link_addr = addr_stoa(&(ifr.ifr_hwaddr));
    if (gbls->link_addr == NULL)
      warning("the iface %s has no mac address associated", gbls->iface);
    else
      debug("HW ADDR: %s", gbls->link_addr);
  }

  for (ifa=ifaddr; ifa!=NULL; ifa=ifa->ifa_next) {
    if (strncmp(gbls->iface, ifa->ifa_name, strlen(gbls->iface)) == 0) {

      /* IPv4 address */
      if (ifa->ifa_addr->sa_family == AF_INET) {
	char *addr = addr_stoa(ifa->ifa_addr);

	if (addr == NULL) {
	  bug(__func__, "invalid IPv4 address");
	} else {
	  gbls->net_addr = addr;
	  debug("IPv4 ADDR: %s", gbls->net_addr);
	}
	
	/* Get netmask */
	addr =  addr_stoa(ifa->ifa_netmask);
	if (addr == NULL) {
	  bug(__func__, "invalid IPv4 address");
	} else {
	  gbls->netmask = addr;
	  debug("IPv4 NETMASK: %s", gbls->netmask);
	}
	/* debug("IPv4 BCAST: %s", addr_stoa(ifa->ifa_broadaddr)); */

      } /* IPv6 address */
      else if (ifa->ifa_addr->sa_family == AF_INET6) {
	char *addr = addr_stoa(ifa->ifa_addr);
	
	if (addr == NULL) {
	  bug(__func__, "invalid IPv6 address");
	} else {
	  gbls->net6_addr = addr;
	  debug("IPv6 ADDR: %s", gbls->net6_addr);

	  /* Get netmask */
	  addr =  addr_stoa(ifa->ifa_netmask);
	  if (addr == NULL) {
	    bug(__func__, "invalid IPv6 address");
	  } else {
	    gbls->netmask6 = addr;
	    debug("IPv6 NETMASK: %s", gbls->netmask6);
	  }
	}
      }
    }
  }

  if (gbls->net_addr == NULL)
    warning("the iface %s has no IPv4 address associated", gbls->iface);

  if (gbls->netmask == NULL)
    warning("the iface %s has no netmask of IPv4 address associated", gbls->iface);

  if (gbls->net6_addr == NULL)
    warning("the iface %s has no IPv6 address associated", gbls->iface);
  
  if (gbls->netmask6 == NULL)
    warning("the iface %s has no netmask of IPv6 address associated", gbls->iface);

  close(fd);
  freeifaddrs(ifaddr);
}
