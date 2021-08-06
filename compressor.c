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

/* C standard includes */
#include <unistd.h>
#include <errno.h>
#include <stdint.h>

/* glib includes */
#include <glib.h>
#include <glib/gprintf.h>

/* lzip LZMA compressor */
#include <lzlib.h>

#include "compressor.h"

gboolean lzip_decompress(int infd, int outfd, int * ret_compressed_size) {
    size_t decompressed_size = 0;
    enum { buffer_size = 1024*128 };
    uint8_t inbuf[buffer_size];
    uint8_t outbuf[buffer_size];
    struct LZ_Decoder * const decoder = LZ_decompress_open();
    if( !decoder || LZ_decompress_errno( decoder ) != LZ_ok ) {
        LZ_decompress_close( decoder );
        exit(55);
    }

    if (ret_compressed_size) {
        (*ret_compressed_size) = 0;
    }

    gboolean ineof = FALSE;
    do {
        const int max_in_size = MIN(LZ_decompress_write_size(decoder), buffer_size);
        ssize_t num_read_compr = 0;
        if( max_in_size > 0 ) {
            num_read_compr = read(infd, inbuf, max_in_size);
            if (num_read_compr == 0) {
                ineof = TRUE;
            } else if (num_read_compr < 0) {
                g_printerr("error reading from chblo file: %s\n", g_strerror(errno));
                exit(56);
            }
            if( num_read_compr != LZ_decompress_write(decoder, inbuf, num_read_compr) ) {
                g_printerr("lzip decompression write failure\n");
                exit(56);
            }
            if (ret_compressed_size) {
                (*ret_compressed_size) += num_read_compr;
            }

            if( num_read_compr < max_in_size || ineof ) {
                LZ_decompress_finish(decoder);
            }
        }

        while(1) {
            const int decompr_size = LZ_decompress_read(decoder, outbuf, buffer_size);
            if( decompr_size > 0 ) {
                ssize_t num_written = write(outfd, outbuf, decompr_size);
                if (num_written < 0) {
                    g_printerr("error writing decompressed chunk block to image: %s\n", g_strerror(errno));
                    exit(57);
                } else if (num_written != decompr_size) {
                    g_printerr("error short write while writing decompressed chunk block to image, expected: %d, wrote: %zd\n", decompr_size, num_written);
                    exit(57);
                }
                decompressed_size += num_written;
            }
            else if( decompr_size <= 0 ) {
                break;
            }
        }
    } while(LZ_decompress_member_finished(decoder) != 1 && LZ_decompress_finished(decoder) != 1);
    LZ_decompress_close(decoder);
    if (0) g_printerr("wrote decompressed %zd\n", decompressed_size);

    return TRUE;
}

size_t lzip_compress(int outfd, uint8_t * data, int len) {
    const unsigned long long member_size = 0x7FFFFFFFFFFFFFFFULL; /* INT64_MAX */
    enum { buffer_size = 1024*128 };
    uint8_t buffer[buffer_size];
    struct Lzma_options {
        int dictionary_size;                /* 4 KiB .. 512 MiB */
        int match_len_limit;                /* 5 .. 273 */
    };
    const struct Lzma_options option_mapping[] =
        {
            {   65535,  16 },           /* -0 (65535,16 chooses fast encoder) */
            { 1 << 20,   5 },           /* -1 */
            { 3 << 19,   6 },           /* -2 */
            { 1 << 21,   8 },           /* -3 */
            { 3 << 20,  12 },           /* -4 */
            { 1 << 22,  20 },           /* -5 */
            { 1 << 23,  36 },           /* -6 */
            { 1 << 24,  68 },           /* -7 */
            { 3 << 23, 132 },           /* -8 */
            { 1 << 25, 273 } };         /* -9 */
    struct Lzma_options encoder_options = option_mapping[6]; /* default = "-6" */
    if( encoder_options.dictionary_size > len ) {
        encoder_options.dictionary_size = len;
    }
    if( encoder_options.dictionary_size < LZ_min_dictionary_size() ) {
        encoder_options.dictionary_size = LZ_min_dictionary_size();
    }
    struct LZ_Encoder * const encoder =
        LZ_compress_open( encoder_options.dictionary_size,
                          encoder_options.match_len_limit,
                          member_size );

    if( !encoder || LZ_compress_errno( encoder ) != LZ_ok ) {
        if( !encoder || LZ_compress_errno( encoder ) == LZ_mem_error ) {
            g_printerr("Not enough memory. Try a smaller dictionary size.\n");
        } else {
            g_printerr("invalid argument to encoder.\n");
        }
        exit(50);
    }
    size_t total_written = 0;
    int comp_written = 0;

    do {
        while( LZ_compress_write_size(encoder) > 0 ) {
            const int size = MIN(LZ_compress_write_size(encoder), len-comp_written);
            int wr;
            if ((wr = LZ_compress_write(encoder, data+comp_written, size)) < 0) {
                if (LZ_compress_errno(encoder) != LZ_ok ) {
                    g_printerr("lzip compression write failure.\n");
                    exit(51);
                }
            }
            comp_written += wr;
            if(comp_written >= len) {
                LZ_compress_finish(encoder);
            }
        }
        int comp_read;
        if ((comp_read = LZ_compress_read(encoder, buffer, buffer_size)) <= 0) {
            if (LZ_compress_errno(encoder) != LZ_ok ) {
                g_printerr("lzip compression read failure.\n");
                exit(51);
            }
        }
        if (write(outfd, buffer, comp_read) != comp_read) {
            g_printerr("error writing out compressed chunk: %s\n", g_strerror(errno));
            exit(52);
        }
        total_written += comp_read;
    } while(LZ_compress_finished(encoder) != 1);

    /* save some compression stats */
    const unsigned long long in_size = LZ_compress_total_in_size(encoder);
    const unsigned long long out_size = LZ_compress_total_out_size(encoder);
    if( in_size == 0 || out_size == 0 ) {
        g_printerr("no data compressed.\n");
    } else {
        g_printerr("%6.3f:1, %5.2f%% ratio, %5.2f%% saved, %llu in, %llu out.\n",
                   (double)in_size / out_size,
                   ( 100.0 * out_size ) / in_size,
                   100.0 - ( ( 100.0 * out_size ) / in_size ),
                   in_size, out_size );
    }
    LZ_compress_close(encoder);
    return total_written;
}
