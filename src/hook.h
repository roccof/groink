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
#ifndef GROINK_HOOK_H
#define GROINK_HOOK_H

typedef enum _grk_hook_data_type {
  HOOKDATA_NONE,
  HOOKDATA_PACKET
} hookdata_type_t;

typedef enum _grk_hook_event {
  HOOK_PRE_START_SNIFF,     /* Pre start sniffing */
  HOOK_AT_EXIT,             /* Called at exit */
  HOOK_ON_ERROR,            /* Called on error */
  HOOK_RECEIVED,            /* Packet received */
  HOOK_ARP,                 /* Arp packet received */
  HOOK_TCP,                 /* Tcp packet received */
  HOOK_UDP,                 /* Udp packet received */
  HOOK_ICMP                 /* Icmp packet received */
} hookevent_t;

typedef struct _grk_hook_data {
  hookdata_type_t type;
  void *data;
} hookdata_t;

/* Hook callback function */
typedef void(*hook_cb_t)(hookdata_t *data);

void hook_cleanup();
void hook_register(hookevent_t event, hook_cb_t callback);
void hook_unregister(hookevent_t event, hook_cb_t callback);
void hook_event(hookevent_t event, hookdata_t *data);

#endif /* GROINK_HOOK_H */

