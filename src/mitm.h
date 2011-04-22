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
#ifndef GROINK_MITM_H
#define GROINK_MITM_H

#define MITM_MAX_OPTIONS 100

typedef enum _grk_mitm_state {
  MITM_STATE_START,
  MITM_STATE_STOP
} mitm_state_t;

typedef void (* mitm_callback)();

void mitm_start();
void mitm_stop();
int is_valid_mitm_attack(char *name);

/* MiTM ARP Poisoning */
/* void mitm_start_arp_poisoning(); */
/* void mitm_stop_arp_poisoning(); */

#endif /* GROINK_MITM_H*/
