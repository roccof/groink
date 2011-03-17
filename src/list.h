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
#ifndef GROINK_LIST_H
#define GROINK_LIST_H

/* List */
typedef struct _list {
  struct _elem *head;  /* First element of the list */
  int size;            /* List size */
} List;

/* List element */
typedef struct _elem Element;

/* Callback function used to compare two elements */
typedef int(*list_cmp_callback)(void *e1, void *e2);

/* Callback function used to remove the element content */
typedef void(*list_rm_content_callback)(void *content);

/* IMPORTANT: MUST BE USED ONLY FOR LIST SCANNING AND NOT FOR DELTE AN ELEMENT!!! */
#define LIST_FOREACH(curr, list)				\
  for(curr=(list)->head; curr!=NULL; curr=list_next((curr)))

void list_init(List *);

void list_add_element(List *, void *);
void list_add_element_in_head(List *, void *);

void list_del_element(List *, Element *);

void *list_elem_content(Element *);

int list_has_next(Element *);
Element *list_next(Element *);

int list_has_prev(Element *);
Element *list_prev(Element *);

int list_is_empty(List *list);

int list_contains(List *list, void *content, list_cmp_callback cb);

void list_merge(List *l1, List *l2);

void list_free(List *list, list_rm_content_callback cb);

#endif /* GROINK_LIST_H */
