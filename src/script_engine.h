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
#ifndef GROINK_SCRIPT_ENGINE_H
#define GROINK_SCRIPT_ENGINE_H

#include "packet.h"

#define SCRIPT_DIR "scripts"
#define SCRIPT_EXT ".lua"
#define SCRIPT_DB "scripts.db"

#define MAX_SCRIPT_NAME 4096
#define MAX_SCRIPT_ARGS 50

void se_open();
void se_close();
char *append_script_dir(char *script_name);
void se_proc_packet(packet_t *p);

#endif /* GROINK_SCRIPT_ENGINE_H */
