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
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "config.h"
#include "debug.h"
#include "globals.h"
#include "base.h"

void fatal(const char *where, const char *message, ...)
{
  va_list ap;

#ifdef GROINK_DEBUG
  fprintf(stderr, COLORB_RED"[!!]"COLOR_NORMAL" FATAL in %s: ", where);
#else
  fprintf(stderr, "[!!] FATAL: ");
#endif

  va_start(ap, message);
  vfprintf(stderr, message, ap);
  va_end(ap);

  fprintf(stderr, "\n");

  exit(-1);
}

void se_fatal(const char *message, ...)
{
  va_list ap;

  fprintf(stderr, COLORB_RED"[!!]"COLOR_NORMAL" SE FATAL: ");

  va_start(ap, message);
  vfprintf(stderr, message, ap);
  va_end(ap);

  fprintf(stderr, "\n");

  exit(-1);
}

void debug(const char *message, ...)
{
#ifdef GROINK_DEBUG

  va_list ap;

  fprintf(stderr, "[*] DEBUG: ");

  va_start(ap, message);
  vfprintf(stderr, message, ap);
  va_end(ap);

  fprintf(stderr, "\n");

#endif
}

void se_debug(const char *message, ...)
{
  va_list ap;

  if(gbls->script_debug_mode)
    {
      fprintf(stderr, "[*] SE DEBUG: ");
      
      va_start(ap, message);
      vfprintf(stderr, message, ap);
      va_end(ap);
      
      fprintf(stderr, "\n");
    }
}

void bug(const char *where, const char *message, ...)
{
  va_list ap;

  fprintf(stderr, COLORB_RED"[!!]"COLOR_NORMAL" Bug in %s: ", where);

  va_start(ap, message);
  vfprintf(stderr, message, ap);
  va_end(ap);

  fprintf(stderr, "\n");
  fprintf(stderr, "Please send this bugs to: %s\n", PACKAGE_BUGREPORT);

  exit(-1);
}

void warning(const char *message, ...)
{
  va_list ap;

  fprintf(stderr, COLORB_YELLOW"[*]"COLOR_NORMAL" WARNING: ");

  va_start(ap, message);
  vfprintf(stderr, message, ap);
  va_end(ap);

  fprintf(stderr, "\n");
}

void se_warning(const char *message, ...)
{
  va_list ap;

  fprintf(stderr, COLORB_YELLOW"[*]"COLOR_NORMAL" SE WARNING: ");

  va_start(ap, message);
  vfprintf(stderr, message, ap);
  va_end(ap);

  fprintf(stderr, "\n");
}

void message(const char *message, ...)
{
  va_list ap;

  printf("[+] ");

  va_start(ap, message);
  vprintf(message, ap);
  va_end(ap);

  printf("\n");
}
