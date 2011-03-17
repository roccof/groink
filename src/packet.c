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
#include "debug.h"
#include "packet.h"
#include "globals.h"
#include "netutil.h"

static void merge_header_data(Packet *p, Header *h)
{
  unsigned char *new = NULL;

  /* Merge packet raw data and header data */
  if (p->num_headers == 1) {
    p->rawdata = (unsigned char *)safe_alloc(h->len);
    memcpy(p->rawdata, h->data, h->len);
    p->len = h->len;
    h->data = p->rawdata;
    } else {
    new = (unsigned char *)safe_alloc(p->len + h->len);
    memcpy(new, p->rawdata, p->len);
    memcpy((new + p->len), h->data, h->len);
    free(p->rawdata);
    p->rawdata = new;
    p->len = p->len + h->len;
    h->data = ((p->rawdata + p->len) - h->len);
  }
}

Header *packet_add_header(Packet *p, Proto proto, void *data, size_t len)
{
  Header *h = NULL;
  Header *last = NULL;

  h = (Header *)safe_alloc(sizeof(Header));
  h->proto = proto;
  h->data = data;
  h->len = len;
  h->next = NULL;
  h->decoding_errors = 0;
  h->packet = p;

  /* Insert the header into the packet */

  if (p->headers == NULL) {
    /* Is the first header */
    p->headers = h;
  } else {
    /* Get last header */
    for(last=p->headers; last->next!=NULL; last=last->next);
    
    /* Append the header */
    last->next = h;
  }

  p->num_headers++;

  if (!HAS_FLAG(p, PACKET_FLAG_DECODED))
    merge_header_data(p, h);

  return h;
}

void packet_init(Packet *p)
{
  myassert(p != NULL);

  p->rawdata = NULL;
  p->len = 0;
  p->edit_rawdata = NULL;
  p->edit_len = 0;
  p->headers = NULL;
  p->num_headers = 0;
  p->flags = 0;
  p->hw_srcaddr = NULL;
  p->hw_dstaddr = NULL;
  p->net_srcaddr = NULL;
  p->net_dstaddr = NULL;
}

/* Free packet memory */
void packet_free(Packet *p) // XXX FIXME
{
  Header *h = NULL;
  Header *t = NULL;

  h = p->headers;

  /* Free all headers memory */
  while (h != NULL) {
    t = h;
    h = h->next;
    
    free(t); /* Free header memory */
    t = NULL;
  }

  free(p->rawdata);

  if (p->edit_rawdata != NULL)
    free(p->edit_rawdata);

  if (p->hw_srcaddr != NULL)
    free(p->hw_srcaddr);

  if (p->hw_dstaddr != NULL)
    free(p->hw_dstaddr);

  if (p->net_srcaddr != NULL)
    free(p->net_srcaddr);

  if (p->net_dstaddr != NULL)
    free(p->net_dstaddr);
}

/* Control if the packet contains a specific header */
int packet_contains_header(Packet *p, Proto proto)
{
  Header *h = p->headers;

  while (h != NULL) {
    if(h->proto == proto)
      return 1;
    h = h->next;
  }
  return 0;
}

Header *packet_get_header(Packet *p, Proto proto)
{
  Header *h = p->headers;

  while (h != NULL) {
    if(h->proto == proto)
      return h;
    h = h->next;
  }
  return NULL;
}
