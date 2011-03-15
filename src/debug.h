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
#ifndef GROINK_DEBUG_H
#define GROINK_DEBUG_H

void fatal(const char *, const char *, ...);
/* void se_fatal(const char *message, ...); */
void debug(const char *, ...);
/* void se_debug(const char *, ...); */
void bug(const char *, const char *, ...);
void warning(const char *, ...);
/* void se_warning(const char *, ...); */
void message(const char *, ...);

#define myassert(v)							\
  if(!(v))								\
    bug(__func__, "assertion failed at %s:%d", __FILE__, __LINE__);

#endif /* GROINK_DEBUG_H */
