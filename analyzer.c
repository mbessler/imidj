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

/* glib includes */
#include <glib.h>
#include <glib/gprintf.h>

#include "imidj.h"
#include "analyzer.h"
#include "chidx.h"
#include "chunker.h"
#include "chblo.h"

static gchar* analyzer_index_file = NULL;
static gboolean analyzer_dump_chunksums = FALSE;
static gboolean analyzer_dump_not_header = FALSE;
static gboolean analyzer_dump_chunkpaths = FALSE;
static gchar** analyzer_rest = NULL;




GOptionEntry analyzer_entries[] = {
    /* imidj analyze --chunksums --no-header INDEX */

    /* optional args */
    {"chunksums", '\0', 0, G_OPTION_ARG_NONE, &analyzer_dump_chunksums, "Also dump the chunksums, not just the header", NULL},
    {"no-header", '\0', 0, G_OPTION_ARG_NONE, &analyzer_dump_not_header, "Skip dumping the header, useful with --chunksums", NULL},
    {"chunkpaths", '\0', 0, G_OPTION_ARG_NONE, &analyzer_dump_chunkpaths, "Dump only the relative chunkpaths (implies --no-header)", NULL},
    {"verbose", 'v', 0, G_OPTION_ARG_NONE, &opt_verbose, "Increase output verbosity", NULL },
    /* general */
    {"version", 'V', 0, G_OPTION_ARG_NONE, &opt_version, "Show version information", NULL },
    /* remaining args */
    {G_OPTION_REMAINING, 0, 0, G_OPTION_ARG_FILENAME_ARRAY, &analyzer_rest, NULL, NULL},
    {0}
};


static int analyzer_main(void)
{
    if (! analyzer_dump_chunkpaths) {
        g_print("analyzing index '%s'\n", analyzer_index_file);
    }

    if (! g_file_test(analyzer_index_file, (G_FILE_TEST_EXISTS | G_FILE_TEST_IS_REGULAR))) {
        g_printerr("index file not found: '%s'\n", analyzer_index_file);
        exit(60);
    }

    char * index_path = realpath(analyzer_index_file, NULL);
    if (index_path == NULL) {
        g_printerr("index_path is NULL: %s\n", g_strerror(errno));
        exit(33);
    }

    /* load chunk index file */
    GPtrArray *chunk_list = g_ptr_array_new_with_free_func((GDestroyNotify)chunk_record_free_func);

    chidx_hdr_t hdr;
    chidx_hdr2_t * hdr2;
    parse_chidx(index_path, &hdr, &hdr2, chunk_list);
    if (hdr2 == NULL) {
        g_printerr("hdr2 is NULL: %s\n", g_strerror(errno));
        exit(34);
    }

    if (analyzer_dump_chunkpaths) {
        analyzer_dump_chunksums = FALSE;
        analyzer_dump_not_header = TRUE;

        for (unsigned int i = 0; i < chunk_list->len; i++)
        {
            chidx_chunk_record_t * record = g_ptr_array_index(chunk_list, i);
            gchar * hexdigest = hexlify_digest(hdr.chunkhash_type, record->chunkhash);
            if (hexdigest==NULL) {
                g_printerr("memory allocation failed (at %s:%d): %s\n", __FILE__, __LINE__, g_strerror(errno));
                exit(9);
            }
            g_print("chunks/%02x/%s.chblo" CHUNK_EXT "\n", record->chunkhash[0], hexdigest);
            free(hexdigest);
        }
    }

    if (! analyzer_dump_not_header) {
        g_print("Chunk Index File Format Version: %d\n", hdr.formatversion);
        g_print("Chunker Window Size: 0x%08x\n", hdr.winsize);
        g_print("Chunker Chunk Mask: 0x%08x\n", hdr.chunkmask);
        g_print("Chunker Min Chunk Size: %d\n", hdr.minchunksize);
        g_print("File Hash Type: %s\n", hashname_from_hashtype(hdr.fullfilehash_type));
        g_print("File Hash Length: %d\n", hdr.fullfilehash_len);
        g_print("Chunk Hash Type: %s\n", hashname_from_hashtype(hdr.chunkhash_type));
        g_print("Chunk Hash Length: %d\n", hdr.chunkhash_len);

        size_t chunk_min = SIZE_MAX;
        size_t chunk_max = 0;

        unsigned int num_chunks = 0;
        off_t imglen = 0;
        for (unsigned int i = 0; i < chunk_list->len; i++, num_chunks++)
        {
            chidx_chunk_record_t * record = g_ptr_array_index(chunk_list, i);
            imglen += record->l;
            if (record->l < chunk_min) {
                chunk_min = record->l;
            }
            if (record->l > chunk_max) {
                chunk_max = record->l;
            }
        }

        g_print("Number of Chunks: %d\n", num_chunks);
        g_print("Chunk Min Size: %zd\n", chunk_min);
        g_print("Chunk Max Size: %zd\n", chunk_max);
        /*  file checksum */
        gchar * hexdigest = hexlify_digest(hdr.fullfilehash_type, hdr2->fullfilehash);
        if (hexdigest==NULL) {
            g_printerr("memory allocation failed (at %s:%d): %s\n", __FILE__, __LINE__, g_strerror(errno));
            exit(9);
        }
        g_print("Image File Checksum: %s\n", hexdigest);
        free(hexdigest);
        g_print("Image File Size: %jd\n", imglen);
    }

    if (analyzer_dump_chunksums) {
        off_t offset=0;
        for (unsigned int i = 0; i < chunk_list->len; i++)
        {
            chidx_chunk_record_t * record = g_ptr_array_index(chunk_list, i);
            gchar * hexdigest = hexlify_digest(hdr.chunkhash_type, record->chunkhash);
            if (hexdigest==NULL) {
                g_printerr("memory allocation failed (at %s:%d): %s\n", __FILE__, __LINE__, g_strerror(errno));
                exit(9);
            }
            g_print("Chunk #%d offset=0x%08jx size=%d chunksum=%s\n", i, offset, record->l, hexdigest);
            free(hexdigest);
            offset +=record->l;
        }
    }
    g_free(hdr2);
    free(index_path);
    g_ptr_array_free(chunk_list, TRUE);
    return (0);
}

int analyze_args(int argc, char ** argv)
{
    GOptionContext * context = g_option_context_new ("analyze <INDEX>");
    g_option_context_set_help_enabled(context, TRUE);
    g_option_context_add_main_entries(context, analyzer_entries, NULL);
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
    g_option_context_free(context);

    if (analyzer_rest == NULL || analyzer_rest[0] == NULL)
    {
        g_printerr("%s: missing argument: INDEX\n", g_get_prgname());
        exit(1);
    }
    if (analyzer_rest[1] != NULL)
    {
        g_printerr("%s: too many arguments\n", g_get_prgname());
        exit(1);
    }

    analyzer_index_file = g_strdup(analyzer_rest[0]);
    int ret = analyzer_main();
    g_free(analyzer_index_file);
    return ret;
}

