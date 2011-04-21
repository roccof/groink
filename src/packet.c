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

#include "base.h"
#include "packet.h"
#include "globals.h"
#include "utlist.h"

static void merge_header_data(packet_t *p, header_t *h)
{
  unsigned char *new = NULL;

  /* Merge packet raw data and header data */
  if (p->num_headers == 1) {
    p->data = (unsigned char *)safe_alloc(h->len);
    memcpy(p->data, h->data, h->len);
    p->len = h->len;
    h->data = p->data;
    } else {
    new = (unsigned char *)safe_alloc(p->len + h->len);
    memcpy(new, p->data, p->len);
    memcpy((new + p->len), h->data, h->len);
    free(p->data);
    p->data = new;
    p->len = p->len + h->len;
    h->data = ((p->data + p->len) - h->len);
  }
}

header_t *packet_append_header(packet_t *p, char *proto, _uint8 *data, size_t len)
{
  header_t *h = NULL;

  h = (header_t *)safe_alloc(sizeof(header_t));
  h->proto = proto;
  h->data = data;
  h->len = len;
  h->next = NULL;
  h->prev = NULL;
  h->decoding_errors = 0;
  h->packet = p;

  /* Append the header into the packet */
  DL_APPEND(p->headers, h);
  p->num_headers++;

  if (!PKT_HAS_FLAG(p, PACKET_FLAG_DECODED))
    merge_header_data(p, h);

  return h;
}

static void packet_init(packet_t *p)
{
  p->headers = NULL;
  p->num_headers = 0;
  p->flags = 0;
  p->hw_srcaddr = NULL;
  p->hw_dstaddr = NULL;
  p->net_srcaddr = NULL;
  p->net_dstaddr = NULL;
}

packet_t *packet_new(_uint8 *data, size_t len)
{
  packet_t *p = (packet_t *)safe_alloc(sizeof(packet_t));
  p->data = (_uint8 *)safe_alloc(len);
  memcpy(p->data, data, len);
  p->len = len;
  packet_init(p);

  return p;
}

packet_t *packet_new_empty()
{
  packet_t *p = (packet_t *)safe_alloc(sizeof(packet_t));
  p->data = NULL;
  p->len = 0;
  packet_init(p);

  return p;
}

/* Free packet memory */
void packet_free(packet_t *p)
{
  header_t *h = NULL;
  header_t *t = NULL;

  /* Free all headers memory */
  DL_FOREACH_SAFE (p->headers, h, t) {
    DL_DELETE(p->headers, h);
    free(h);
    h = NULL;
  }

  /* Free packet data */
  if (p->data != NULL) {
    free(p->data);
    p->data = NULL;
  }

  if (p->hw_srcaddr != NULL) {
    free(p->hw_srcaddr);
    p->hw_srcaddr = NULL;
  }

  if (p->hw_dstaddr != NULL) {
    free(p->hw_dstaddr);
    p->hw_dstaddr = NULL;
  }

  if (p->net_srcaddr != NULL) {
    free(p->net_srcaddr);
    p->net_srcaddr = NULL;
  }
    
  if (p->net_dstaddr != NULL) {
    free(p->net_dstaddr);
    p->net_dstaddr = NULL;
  }

  /* Fee packet memory */
  free(p);
}

/* Control if the packet contains a specific header */
int packet_contains_header(packet_t *p, char *proto)
{
  header_t *h = NULL;

  DL_FOREACH (p->headers, h) {
    if (strncmp(h->proto, proto, strlen(h->proto)) == 0)
      return 1;
  }
  return 0;
}

header_t *packet_get_header(packet_t *p, char *proto)
{
  header_t *h = NULL;

  DL_FOREACH (p->headers, h) {
    if (strncmp(h->proto, proto, strlen(h->proto)) == 0)
      return h;
  }
  return NULL;
}
