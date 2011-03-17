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
#ifndef GROINK_BASE_H
#define GROINK_BASE_H

#include <endian.h>
#include <stdlib.h>

/* Control big/little endian convention for current host */
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define LENDIAN
#undef BENDIAN
#elif __BYTE_ORDER == __BIG_ENDIAN
#define BENDIAN
#undef LENDIAN
#else
#error "Please fix <bits/endian.h>"
#endif

#define GROINK_DATADIR INSTALL_DATADIR"/"PACKAGE

#define COLOR_BOLD       "\033[1m"
#define COLOR_NORMAL     "\033[0m"
#define COLOR_RED        "\033[31m"
#define COLORB_RED       "\033[31m"COLOR_BOLD
#define COLOR_YELLOW     "\033[33m"
#define COLORB_YELLOW    "\033[33m"COLOR_BOLD
#define COLOR_GREEN      "\033[32m"
#define COLORB_GREEN     "\033[32m"COLOR_BOLD
#define COLOR_BLUE       "\033[34m"
#define COLORB_BLUE      "\033[34m"COLOR_BOLD
#define COLOR_CYAN       "\033[36m"
#define COLORB_CYAN      "\033[36m"COLOR_BOLD

#define CR '\r'
#define LF '\n'
#define SP ' '
#define HT '\t'
#define CRLF "\r\n"

#define BITNO_32(_x) (((_x) >> 16) ? 16 + BITNO_16((_x) >> 16) : BITNO_16((_x)))
#define BITNO_16(_x) (((_x) >> 8) ? 8 + BITNO_8((_x) >> 8) : BITNO_8((_x)))
#define BITNO_8(_x) (((_x) >> 4) ? 4 + BITNO_4((_x) >> 4) : BITNO_4((_x)))
#define BITNO_4(_x) (((_x) >> 2) ? 2 + BITNO_2((_x) >> 2) : BITNO_2((_x)))
#define BITNO_2(_x) (((_x) & 2) ? 1 : 0)
#define BIT(_n)	(1 << _n)

typedef unsigned char _uint8;
typedef unsigned short _uint16;
typedef unsigned int _uint32;
typedef unsigned long _uint64;

typedef char _int8;
typedef short _int16;
typedef int _int32;
typedef long _int64;

typedef unsigned char _uchar;
typedef unsigned short _ushort;
typedef unsigned int _uint;
typedef unsigned long _ulong;

/* Value to name struct */
struct _vton
{
  char *name;
  int value;
};

char *str_concat(char *str, ...);
char *str_toupper(char *str);
char *str_tolower(char *str);
void *safe_alloc(size_t size);
void *safe_realloc(void *ptr, size_t size);
char *fake_unicode(unsigned char *bytes, int len);
char *hex_string(unsigned char *bytes, int len);
void load_iface_info();

#endif /* GROINK_BASE_H */
