/*
 * This file is part of the IMIDJ - IMage Incremental Deltafragment Joiner
 * (https://github.com/mbessler/imidj)
 *
 * Copyright (c) 2019-21 Manuel Bessler
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#pragma once
#include <stdint.h>

#define DEFAULT_WHOLEFILE_HASH IMIDJ_HASH_SHA256
#define DEFAULT_CHUNK_HASH     IMIDJ_HASH_MD5

typedef enum {
    IMIDJ_HASH_MD5 = 0,
    IMIDJ_HASH_SHA256 = 1,
    /* future versions may define others here,
       but must increase the 'formatversion' field */
} hash_type_t;

const gchar * hashname_from_hashtype(hash_type_t htype);
uint16_t hashsize_from_hashtype(hash_type_t htype);
gchar * hexlify_digest(hash_type_t htype, uint8_t digest[]);
uint8_t * calculate_digest(hash_type_t htype, uint8_t * data, ssize_t len);
uint8_t * calculate_digest_file(hash_type_t htype, char * filename);

