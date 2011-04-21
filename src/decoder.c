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
#include "decoder.h"
#include "protos.h"
#include "protos_name.h"
#include "debug.h"
#include "globals.h"

int start_decoding(packet_t *p)
{
  unsigned int status = 0;

  PKT_ADD_FLAG(p, PACKET_FLAG_DECODED);

  switch (gbls->dlt) {

      /* Raw IP */
    case DLT_RAW:
      status = call_decoder(PROTO_NAME_IPV4, p, p->data, p->len);
      break;

      /* Ethernet 10/100/1000 header */
    case DLT_EN10MB:
      status = call_decoder(PROTO_NAME_ETHER, p, p->data, p->len);
      break;

      /* IEEE 802.11 wireless lan header */
    /* case DLT_IEEE802_11: */
    /*   status = call_decoder("asd", p, p->data, p->len); */
    /*   break; */

      /* IEEE 802.11 radiotap header */
    /* case DLT_IEEE802_11_RADIO: */
    /*   status = call_decoder("asd", p, p->data, p->len); */
    /*   break; */
      
    default:
      debug("data link protocol '%s' not supported", 
	    pcap_datalink_val_to_name(gbls->dlt));
      status = call_decoder(PROTO_NAME_RAW, p, p->data, p->len);
    }

  return status;
}

int call_decoder(char *proto_name, packet_t *p, const _uint8 *bytes, size_t len)
{
  proto_t *proto = proto_get_byname(proto_name);

  if (proto != NULL) {
    myassert(proto->decoder != NULL);
    return (*proto->decoder)(p, bytes, len);
  }
  return DECODER_NOT_FOUND;
}

int call_decoder_byport(int port, packet_t *p, const _uint8 *bytes, size_t len)
{
  proto_t *proto = proto_get_byport(port);

  if (proto != NULL) {
    myassert(proto->decoder != NULL);
    return (*proto->decoder)(p, bytes, len);
  }
  return DECODER_NOT_FOUND;
}

