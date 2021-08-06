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
#include <fcntl.h>
#include <errno.h>
#include <inttypes.h>

/* glib includes */
#include <glib.h>
#include <glib/gstdio.h>
#include <glib/gprintf.h>

#include "imidj.h"
#include "differ.h"
#include "chidx.h"
#include "chunker.h"

static gchar* differ_image1 = NULL;
static gchar* differ_image2 = NULL;
static gchar** differ_rest = NULL;


GOptionEntry differ_entries[] = {
    /* imidj diff <IMAGE1> <IMAGE2> */
    {"verbose", 'v', 0, G_OPTION_ARG_NONE, &opt_verbose, "Increase output verbosity", NULL },
    /* general */
    {"version", 'V', 0, G_OPTION_ARG_NONE, &opt_version, "Show version information", NULL },
    /* remaining args */
    {G_OPTION_REMAINING, 0, 0, G_OPTION_ARG_FILENAME_ARRAY, &differ_rest, NULL, NULL},
    {0}
};


static int differ_main(void)
{
    char * image_path[2];
    uint8_t * wholefile_digest[2];
    GPtrArray * chunk_records[2];
    GHashTable * chunk_refcnt_table[2] = {NULL, NULL};
    gchar * image_dir[2];
    gchar * image_fname[2];

    image_path[0] = realpath(differ_image1, NULL);
    image_path[1] = realpath(differ_image2, NULL);
    if (image_path[0] == NULL || image_path[1] == NULL) {
        g_printerr("image_path[0|1] is NULL: %s\n", g_strerror(errno));
        exit(33);
    }

    for(int idx=0; idx < 2; idx++) {
        if (image_path[idx] == NULL) g_printerr("image_path is NULL: %s\n", g_strerror(errno));
        /* todo error handling*/

        image_dir[idx] = g_path_get_dirname(image_path[idx]);
        image_fname[idx] = g_path_get_basename(image_path[idx]);

        if (! g_file_test(image_path[idx], (G_FILE_TEST_EXISTS | G_FILE_TEST_IS_REGULAR))) {
            g_printerr("image file not found: '%s'\n", image_path[idx]);
            exit(30);
        }

        /* open image */
        int fd = g_open(image_path[idx], O_RDONLY);
        if (fd < 0) {
            g_printerr("Cannot open image file '%s': %s\n", image_path[idx], g_strerror(errno));
            exit(32);
        }

        /* checksum of whole file */
        wholefile_digest[idx] = calculate_digest_file(DEFAULT_WHOLEFILE_HASH, image_path[idx]);

        g_print("indexing...\n");
        chunk_records[idx] = g_ptr_array_new_with_free_func((GDestroyNotify)chunk_record_free_func);
        chunk_refcnt_table[idx] = g_hash_table_new_full(g_bytes_hash, g_bytes_equal, (GDestroyNotify)g_bytes_unref, (GDestroyNotify)free);
        index_a_file(image_path[idx], DEFAULT_CHUNK_HASH, chunk_records[idx], chunk_refcnt_table[idx]);
        g_print("chunk_records = %p\n", (void *)chunk_records[idx]);
        g_close(fd, NULL);
    }

    /* simple diff algorithm as we just want to check if the position, size, and chunksum is the same for each chunk for both files */
    if (chunk_records[0]->len == chunk_records[1]->len) {
        g_print("Both files have %d chunks.\n", chunk_records[0]->len);
    } else {
        g_print("File A has %d chunks, but file B has %d chunks\n", chunk_records[0]->len, chunk_records[1]->len);
    }

    /*unsigned int min_c = (chunk_records[0]->len < chunk_records[1]->len) ? chunk_records[0]->len : chunk_records[1]->len;*/
    unsigned int max_c = (chunk_records[0]->len > chunk_records[1]->len) ? chunk_records[0]->len : chunk_records[1]->len;

    for (unsigned int i = 0; i < max_c; i++)
    {
        chidx_chunk_record_t * record[2] = { NULL, NULL };
        gchar * hexdigest[2] = {NULL, NULL};

        for (int idx=0; idx<2; idx++) {
            if (i < chunk_records[idx]->len) {
                record[idx] = g_ptr_array_index(chunk_records[idx], i);
                /* num should be same as i */
                if (record[idx]->num != i) {
                    g_print("Numbering issue in file %c at %d\n", (idx==0)?'A':'B', i);
                }
            } else {
                record[idx] = NULL;
            }
        }

        g_print("Chunk %d |", i);
        if (i < chunk_records[0]->len && i < chunk_records[1]->len) { /* chunks in both */
            hexdigest[0] = hexlify_digest(DEFAULT_CHUNK_HASH, record[0]->chunkhash);
            hexdigest[1] = hexlify_digest(DEFAULT_CHUNK_HASH, record[1]->chunkhash);
            if (record[0]->offset != record[1]->offset) {
                g_print(" offsets differ: %"PRIu64" vs %"PRIu64" |", record[0]->offset, record[1]->offset);
            } else {
                g_print(" offsets identical %"PRIu64" |", record[0]->offset);
            }
            if (record[0]->l != record[1]->l) {
                g_print(" lengths differ: %d vs %d |", record[0]->l, record[1]->l);
            } else {
                g_print(" lengths identical %d |", record[0]->l);
            }
            if (memcmp(record[0]->chunkhash, record[1]->chunkhash, hashsize_from_hashtype(DEFAULT_CHUNK_HASH)) != 0) {
                g_print("  chunksums differ: %s vs %s |", hexdigest[0], hexdigest[1]);
            } else {
                g_print(" chunksums identical %s |", hexdigest[0]);
            }

        } else if (i < chunk_records[0]->len) { /* chunk exists only in A */
            hexdigest[0] = hexlify_digest(DEFAULT_CHUNK_HASH, record[0]->chunkhash);
            g_print("Only in A: offset=%"PRIu64"  len=%d  chunksum=%s\n", record[0]->offset, record[0]->l, hexdigest[0]);
        } else { /* chunk exists only in B */
            hexdigest[1] = hexlify_digest(DEFAULT_CHUNK_HASH, record[1]->chunkhash);
            g_print("Only in B: offset=%"PRIu64"  len=%d  chunksum=%s\n", record[1]->offset, record[1]->l, hexdigest[1]);
        }

        if( hexdigest[0] != NULL) free(hexdigest[0]);
        if( hexdigest[1] != NULL) free(hexdigest[1]);
        g_print("\n");
    }

    /* cleanup */
    for(int idx=0; idx < 2; idx++) {
        g_hash_table_destroy(chunk_refcnt_table[idx]);
        g_ptr_array_free(chunk_records[idx], TRUE);
        free(wholefile_digest[idx]);
        g_free(image_fname[idx]);
        g_free(image_dir[idx]);
        free(image_path[idx]);
    }

    return 0;
}


int diff_args(int argc, char ** argv) {
    GOptionContext * context = g_option_context_new ("diff <IMAGE1> <IMAGE2>");
    g_option_context_set_help_enabled(context, TRUE);
    g_option_context_add_main_entries(context, differ_entries, NULL);
    g_option_context_set_description(context,
                                     "\n" \
                                     COPYRIGHT_STR "\n" \
                                     LICENSE_STR "\n"
        );
    GError *error = NULL;
    if (!g_option_context_parse (context, &argc, &argv, &error)) {
        g_printerr ("%s\n", error->message);
        g_error_free(error);
        usage(context);
        g_option_context_free(context);
        return(1);
    }

    g_option_context_free (context);

    if (differ_rest == NULL || differ_rest[0] == NULL)
    {
        g_printerr("%s: missing argument: IMAGE1\n", g_get_prgname());
        return(1);
    }
    if (differ_rest[1] == NULL || differ_rest[2] != NULL)
    {
        g_printerr("%s: missing argument: IMAGE2\n", g_get_prgname());
        return(1);
    }
    if (differ_rest[2] != NULL)
    {
        g_printerr("%s: too many arguments\n", g_get_prgname());
        return(1);
    }

    differ_image1 = g_strdup (differ_rest[0]);
    differ_image2 = g_strdup (differ_rest[1]);
    int ret = differ_main();
    g_free(differ_image2);
    g_free(differ_image1);
    return ret;
}
