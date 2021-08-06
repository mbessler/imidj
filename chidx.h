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

/* Version 2+ CHiDX file formats */

#include <stdint.h>

#include "chidx-digest.h"

#define FORMATVERSION (2)
#define WINSIZE (0xfff)
#define CHUNKMASK (0xffff)
#define MINCHUNKSIZE (1024)


/* file header */

typedef struct __attribute__((packed)) {
    char         signature[5];        /*5*/
    uint16_t     formatversion;       /*2*/
    uint32_t     winsize;             /*4*/
    uint32_t     chunkmask;           /*4*/
    uint32_t     minchunksize;        /*4*/
    uint8_t      fullfilehash_type;   /*1*/
    uint16_t     fullfilehash_len;    /*2*/
    uint8_t      chunkhash_type;      /*1*/
    uint16_t     chunkhash_len;       /*2*/
    uint8_t      reserved[231];     /*231*/
} chidx_hdr_t;

typedef struct __attribute__((packed)) {
    uint8_t      undefined;
    uint8_t      fullfilehash[];     /*flexible array member, defined by fullfilehash_len*/
} chidx_hdr2_t;


/* file payload: chunk information */
typedef struct __attribute__((packed)) {
    uint32_t     l;
    uint8_t      chunkhash[];        /*flexible array member, defined by chunkhash_len*/
} chidx_chunk_file_record_t;


typedef struct {
    //chidx_chunk_file_record_t chunk_record;
    uint32_t     l;
    uint32_t     num;
    uint64_t     offset;
    uint8_t      chunkhash[];
} chidx_chunk_record_t;


int index_args(int argc, char ** argv);
void chunk_record_free_func(chidx_chunk_record_t * record);
gboolean parse_chidx(gchar *chidx_filename, chidx_hdr_t * hdr, chidx_hdr2_t ** hdr2p, GPtrArray *chunk_list);
int index_a_file(char * filename, hash_type_t htype, GPtrArray *chunk_records, GHashTable * chunk_refcnt_table);

/**** old v0 .chidx format ****/
typedef struct __attribute__((packed)) {
    uint16_t formatversion; /*2*/
    uint32_t winsize;  /*4*/
    uint32_t chunkmask;  /*4*/
    uint32_t minchunksize; /*4*/
    uint8_t fullfilehash[16];  /*16*/
    /* total: 30bytes */
} chidx_hdr_v0_t; /* header block of chunk index file, minus the file signature itself */
