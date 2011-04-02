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
#ifndef GROINK_DECODER_H
#define GROINK_DECODER_H

#include "packet.h"

#define ADD_ERROR(h, e) ((h)->decoding_errors |= (e))
#define REMOVE_ERROR(h, e) ((h)->decoding_errors &= ~(e))
#define HAS_ERROR(h, e) (((h)->decoding_errors & (e)) == (e))
#define NO_ERRORS 0x00

#define DECODE_FAIL -1
#define DECODE_OK 0
#define DECODER_NOT_FOUND 2

/* Decoder callback function */
typedef int(*decoder_cb_t)(packet_t *p, const _uint8 *bytes, size_t len);

int start_decoding(packet_t *p, const rawpacket_t *rp);
int call_decoder(char *proto_name, packet_t *p, const _uint8 *bytes, size_t len);
int call_decoder_byport(int port, packet_t *p, const _uint8 *bytes, size_t len);

#endif /* GROINK_DECODER_H */
