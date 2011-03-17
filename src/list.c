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
#include <stdlib.h>

#include "debug.h"
#include "base.h"
#include "list.h"

/* List Element */
struct _elem {
  void *content;       /* Current element */
  struct _elem *next;  /* Next element */
  struct _elem *prev;  /* Previous element */
};

void list_init(List *list)
{
  list->head = NULL;
  list->size = 0;
}

void list_add_element(List *list, void *data)
{
  Element *new, *curr;

  new = (Element *)safe_alloc(sizeof(Element));

  new->content = data;

  list->size++;

  if (list->head != NULL) {
    /* Put the new element in the queue */
    for (curr = list->head; curr->next; curr=curr->next);

    curr->next = new;
    new->next = NULL;
    new->prev = curr;
  } else {
    list->head = new;
    new->next = NULL;
    new->prev = NULL;
  }
}

void list_add_element_in_head(List *list, void *data)
{
  Element *new;

  new = (Element *)safe_alloc(sizeof(Element));

  new->content = data;

  list->size++;

  if (list->head != NULL) {
    /* Put the new element in the head */
    new->next = list->head;
    new->prev = NULL;
    list->head->prev = new;
    list->head = new;
  } else {
    list->head = new;
    list->head->next = NULL;
    list->head->prev = NULL;
  }
}

void list_del_element(List *list, Element *elem)
{
  if (elem == NULL || list == NULL)
    return;

  if (elem->prev == NULL) {
    list->head = elem->next;

    if(elem->next != NULL)
      elem->next->prev = NULL;
  } else {
    if(elem->next != NULL)
      elem->next->prev = elem->prev;

    elem->prev->next = elem->next;
  }
  
  list->size--;
  free(elem);
}

void *list_elem_content(Element *e)
{
  if (e != NULL)
    return e->content;
  return NULL;
}

int list_has_next(Element *e)
{
  if (e != NULL)
    return 1;
  return 0;
}

Element *list_next(Element *e)
{
  if (e != NULL)
    return e->next;
  return NULL;
}

int list_has_prev(Element *e)
{
  if (e != NULL)
    return 1;
  return 0;
}

Element *list_prev(Element *e)
{
  if (e != NULL)
    return e->prev;
  return NULL;
}

int list_is_empty(List *list)
{
  if (list->head != NULL)
    return 1;
  return 0;
}

int list_contains(List *list, void *content, list_cmp_callback cb)
{
  Element *curr = NULL;

  if (cb == NULL)
    bug(__func__, "invalid callback function");

  LIST_FOREACH(curr, list) {
    void * c2 = list_elem_content(curr);
    if(cb(content, c2))
      return 1;
  }
  return 0;
}

void list_free(List *list, list_rm_content_callback cb)
{
  Element *curr = list->head;
  Element *del = NULL;

  while (list_has_next(curr)) {
    void *content = list_elem_content(curr);
    
    if(content == NULL)
      bug(__func__, "list element content is NULL");
    
    del = curr;
    curr = list_next(curr);
    list_del_element(list, del);
    
    /* Call the callback function to free the element content */
    if(cb != NULL)
      cb(content);
    }
}

void list_merge(List *l1, List *l2)
{
  Element *curr = NULL;

  LIST_FOREACH(curr, l2) {
      void *e = list_elem_content(curr);

      if(e == NULL)
	bug(__func__, "invalid element content");

      list_add_element(l1, e);
    }  
}
