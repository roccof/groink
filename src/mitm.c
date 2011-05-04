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
#include <string.h>

#include "base.h"
#include "globals.h"
#include "mitm.h"

struct _mitm_attack {
  char *name;
  mitm_callback start_cb;
  mitm_callback stop_cb;
};

struct _mitm_attack mitms[] = {
  {"arp", &mitm_start_arp_poisoning, &mitm_stop_arp_poisoning},
  {NULL, NULL, NULL}
};

void mitm_start()
{
  int i = 0;

  if (gbls->mitm == NULL || gbls->mitm_state == MITM_STATE_START)
    return;

  for (i=0; mitms[i].name!=NULL; i++)
    if (strcmp(mitms[i].name, gbls->mitm) == 0) {
      gbls->mitm_state = MITM_STATE_START;
      
      /* Lunch MiTM ttack */
      (mitms[i].start_cb)();
      return;
    }
}

void mitm_stop()
{
  int i = 0;

  if (gbls->mitm == NULL || gbls->mitm_state == MITM_STATE_STOP)
    return;

  for (i=0; mitms[i].name!=NULL; i++)
    if (strcmp(mitms[i].name, gbls->mitm) == 0) {
      gbls->mitm_state = MITM_STATE_STOP;
      
      /* Stop MiTM ttack */
      (mitms[i].stop_cb)();
      return;
    }
}

int is_valid_mitm_attack(char *name)
{
  int i = 0;

  if (name == NULL)
    return 0;

  for (i=0; mitms[i].name!=NULL; i++)
    if (strcmp(mitms[i].name, name) == 0)
      return 1;
  return 0;
}
