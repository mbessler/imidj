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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

/* glib includes */
#include <glib.h>
#include <glib/gstdio.h>

#include "chblo.h"
#include "chidx.h"
#include "compressor.h"
#include "chidx-digest.h"

int write_chblos(char * img_filename, char * outputdir, GPtrArray *chunk_records)
{
    g_assert(img_filename != NULL);
    g_assert(outputdir != NULL);
    g_assert(chunk_records != NULL);

    /* open image */
    int imgfd = g_open(img_filename, O_RDONLY);
    if (imgfd < 0) {
        g_printerr("Cannot open image file '%s': %s\n", img_filename, g_strerror(errno));
        exit(32);
    }

    for (unsigned int i = 0; i < chunk_records->len; i++)
    {
        chidx_chunk_record_t * record = g_ptr_array_index(chunk_records, i);
        /* read chunk from image */
        if (lseek(imgfd, record->offset, SEEK_SET) < 0) {
            g_printerr("seek failed while writing chunk blobs in %s: %s\n", img_filename, g_strerror(errno));
            exit(120);
        }
        uint8_t * chunk_data = g_malloc(record->l);
        if (chunk_data == NULL) {
            g_printerr("memory allocation error at %s:%d\n", __FILE__, __LINE__);
            exit(9);
        }
        if (read(imgfd, chunk_data, record->l) != (ssize_t)record->l) {
            g_printerr("could not read chunk from image file for writing to chunk store '%s': %s\n", img_filename, g_strerror(errno));
            exit(41);
        }

        /* write chunk to chunkstore */
        char * chblo_dir = g_strdup_printf("%s/chunks/%02x", outputdir, record->chunkhash[0]);
        char * chblo_path = NULL;
        gchar * hexdigest = hexlify_digest(DEFAULT_CHUNK_HASH, record->chunkhash);
        chblo_path = g_strdup_printf("%s/%s.chblo" CHUNK_EXT, chblo_dir, hexdigest);
        g_free(hexdigest);

        if (g_mkdir_with_parents(chblo_dir, 0755) < 0) {
            g_printerr("Cannot create output directory for chunk '%s': %s\n", chblo_dir, g_strerror(errno));
            exit(38);
        }

        if (g_file_test(chblo_path, G_FILE_TEST_EXISTS)) {
            g_print("chunk block already exists in chunk store: '%s'\n", chblo_path);
        } else {
            int chblofd = g_open(chblo_path, O_CREAT|O_WRONLY|O_TRUNC, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
            if (chblofd < 0) {
                g_printerr("Cannot create chunk chblo file '%s': %s\n", chblo_path, g_strerror(errno));
                exit(39);
            }

            size_t total_written = lzip_compress(chblofd, chunk_data, record->l);
            g_print("chunk of size %d LZIP compressed to %zd\n", record->l, total_written);
            g_print("wrote %zd bytes, expected %d\n", total_written, record->l);
            g_close(chblofd, NULL);
        }

        g_free(chunk_data);
        g_free(chblo_dir);
        g_free(chblo_path);
    }
    g_close(imgfd, NULL);
    return(0);
}
