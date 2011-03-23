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
#ifndef GROINK_HASHTABLE_H
#define GROINK_HASHTABLE_H

#include "debug.h"
#include "base.h"
#include "uthash.h"

#undef uthash_fatal
#define uthash_fatal(msg) fatal("uthash", msg);

/* #undef uthash_malloc */
/* #define uthash_malloc(sz) safe_alloc(sz); */

#endif /* GROINK_HASHTABLE_H*/
