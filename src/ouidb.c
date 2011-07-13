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
#include <stdio.h>
#include <regex.h>

#include "base.h"
#include "netutil.h"
#include "debug.h"
#include "ouidb.h"
#include "utlist.h"

#define DB_FILE GROINK_DATADIR"/data/oui_db.txt"

#define OUI_REGEX "([0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f])"

typedef struct _grk_ouidb {
  char *oui;
  char *company;
  struct _grk_ouidb *next;
} ouidb_t;

static ouidb_t *db = NULL;

int ouidb_load()
{
  FILE *f = NULL;
  char *line = NULL;
  size_t n = 0;
  ssize_t read = 0;
  char *tok = NULL;
  char *saveptr = NULL;
  ouidb_t *entry = NULL; 

  f = fopen(DB_FILE, "r");

  if (f == NULL)
    fatal(__func__, "unable to open oui db file '%s'", DB_FILE);

  while ((read = getline(&line, &n, f)) != -1) {
    /* Copy the line without '\n' character */
    char *l = (char *)safe_alloc(sizeof(char) * read);
    memcpy(l, line, (read - 1));
    l[read - 1] = '\0';
    
    /* OUI */
    tok = strtok_r(l, "|", &saveptr);

    if (tok == NULL)
      goto next;

    entry = (ouidb_t *)safe_alloc(sizeof(ouidb_t));
    entry->oui = strdup(tok);
    
    /* Company name */
    tok = strtok_r(NULL, "|", &saveptr);

    if (tok == NULL) {
      free(entry->oui);
      free(entry);
      goto next;
    }

    entry->company = strdup(tok);

    LL_APPEND(db, entry);
    
  next:
    free(l);
    l = NULL;
    entry = NULL;
  }

  free(line);
  line = NULL;

  fclose(f);

  debug("ouidb loaded");

  return 0;
}

void ouidb_free()
{
  ouidb_t *curr = NULL, *tmp = NULL;
  
  LL_FOREACH_SAFE (db, curr, tmp) {
    LL_DELETE(db, curr);

    free(curr->oui);
    free(curr->company);
    free(curr);
    curr = NULL;
  }

  debug("ouidb free'd");
}

static int is_valid_addr(char *addr)
{
  if ((strcmp(addr, ETHER_BROADCAST) == 0) || (strcmp(addr, ETHER_NULL) == 0))
    return 0;
  return 1;
}

char *ouidb_find_company_by_addr(char *addr)
{
  ouidb_t *e = NULL;
  char *oui = NULL;
  int len = 0;
  regex_t regex;
  regmatch_t *m = NULL;
  char *company = NULL;

  if(!is_ether_addr(addr) || !is_valid_addr(addr))
    return NULL;

  if (regcomp(&regex, OUI_REGEX, REG_EXTENDED | REG_ICASE) != 0)
    bug(__func__, "invalid regex");

  m = (regmatch_t *)safe_alloc(sizeof(regmatch_t));

  if (regexec(&regex, addr, 1, m, 0) == 0) {
    len = (m->rm_eo - m->rm_so + 1);
    oui = (char *)safe_alloc(sizeof(char) * len);
    memcpy(oui, (addr + m->rm_so), (len - 1));
    oui[len - 1] = '\0';
    str_toupper(oui);
    
    LL_FOREACH (db, e) {
      if (strncmp(e->oui, oui, 9) == 0) {
	company = e->company;
	break;
      }
    }

    free(oui);
    oui = NULL;
  }

  regfree(&regex);
  free(m);

  return company;
}

char *ouidb_find_oui_by_company(char *company)
{
  /* TODO */
  return NULL;
}
