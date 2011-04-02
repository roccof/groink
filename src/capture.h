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
#ifndef GROINK_CAPTURE_H
#define GROINK_CAPTURE_H

#include <pcap.h>

#define CAPTURE_THREAD_NAME "sniff"
#define CAPTURE_SNAPLEN 65535
#define CAPTURE_TIMEOUT 0

enum _grk_capture_state {
  CAP_STATE_NONE,        /* sniffing not started  */
  CAP_STATE_STARTED,     /* sniffing started */
};

void capture_engine_init();
void capture_engine_destroy();

void start_sniffing();
void stop_sniffing();

#endif /* GROINK_CAPTURE_H */
