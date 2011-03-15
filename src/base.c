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
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>

#include "base.h"
#include "debug.h"

void *safe_alloc(size_t size)
{
  void *p = NULL;

  p = malloc(size);

  if(p == NULL)
    fatal("safe_alloc", "error while allocating memory, your mem sucks!!!!!");

  bzero(p, size);

  return p;
}

void *safe_realloc(void *ptr, size_t size)
{
  void *p = NULL;

  if(ptr == NULL)
    bug("safe-realloc", "null pointer");

  p = realloc(ptr, size);

  if(p == NULL)
    fatal("safe_realloc", "error while reallocating memory");

  return p;
}

/* Return a printable UNICODE string */
char *fake_unicode(unsigned char *bytes, int len)
{
  unsigned char *byte = NULL;
  int i = 0;
  char *str;

  /* str = buff; */
  /* bzero(str, len + 1); */

  if(bytes == NULL)
    bug("fake_unicode", "the bytes are NULL");

  /* This buffer MUST be freed after */
  str = (char *)safe_alloc(len + 1);

  for(byte=bytes; byte<(bytes+len); byte++)
    {
      if(*byte > 31 && *byte < 127)
	str[i++] = *byte;
      else
	str[i++] = '.';
    }
  str[i] = '\0';

  return str;
}

/* Return an hex string */
char *hex_string(unsigned char *bytes, int len)
{
  unsigned char *byte = NULL;
  int i = 0;
  char *str = NULL;
  char *buffer = NULL;

  if(bytes == NULL)
    bug("hex_string", "the bytes are NULL");

  /* This buffer MUST be freed after */
  str = (char *)safe_alloc((len * 2) + 1);

  buffer = (char *)safe_alloc(4);

  for(byte=bytes; byte<(bytes+len); byte++)
    {
      sprintf(buffer, "%02X", *byte);
      memcpy((str + i), buffer, 2);
      i += 2;
    }

  str[i] = '\0';

  free(buffer);

  return str;
}

/* 
 * This function concatenates arbitrarily many strings.
 * The last  parameter must be NULL.
 */
char *str_concat(char *str, ...)
{
  va_list ap, ap2;
  size_t totlen = 1;  /* Null byte */
  char *result = NULL;
  char *s = NULL;

  va_start(ap, str);
  va_copy(ap2, ap);

  /* Calculate the total length */
  for(s=str; s!=NULL; s=va_arg(ap, char *))
    totlen += strlen(s);

  va_end(ap);

  result = (char *)safe_alloc(totlen);
  
  result[0] = '\0'; /* Add null byte */

  /* Copy the strings. */
  for (s=str; s!=NULL; s=va_arg(ap2, char *))
    strcat(result, s);

  va_end(ap2);

  return result;
}

char *str_toupper(char *str)
{
  int i = 0;

  myassert(str != NULL);

  for(i=0; i<strlen(str); i++)
    {
      if(str[i] > 96 && str[i] < 123)
	str[i] = toupper(str[i]);
    }

  return str;
}
char *str_tolower(char *str)
{
  int i = 0;

  myassert(str != NULL);

  for(i=0; i<strlen(str); i++)
    {
      if(str[i] > 96 && str[i] < 123)
	str[i] = tolower(str[i]);
    }

  return str;
}
