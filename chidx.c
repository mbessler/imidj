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
#include <glib/gprintf.h>

#include "imidj.h"
#include "chidx.h"
#include "chblo.h"
#include "chunker.h"
#include "chidx-digest.h"

static gboolean indexer_index_only = FALSE;
static gboolean indexer_force_overwrite = FALSE;
static gchar** indexer_rest = NULL;
static gchar * indexer_image = NULL;
static gchar * indexer_outdir = NULL;

GOptionEntry indexer_entries[] = {
    /* imidj index --index-only --force-overwrite <IMAGE> <OUTDIR> */
    {"index-only", '\0', 0, G_OPTION_ARG_NONE, &indexer_index_only, "Print index only, do not store chunks", NULL},
    {"force-overwrite", '\0', 0, G_OPTION_ARG_NONE, &indexer_force_overwrite, "Force overwrite index file if it already exists", NULL},
    {"verbose", 'v', 0, G_OPTION_ARG_NONE, &opt_verbose, "Increase output verbosity", NULL },
    /* general */
    {"version", 'V', 0, G_OPTION_ARG_NONE, &opt_version, "Show version information", NULL },
    /* remaining args */
    {G_OPTION_REMAINING, 0, 0, G_OPTION_ARG_FILENAME_ARRAY, &indexer_rest, NULL, NULL},
    {0}
};



void chunk_record_free_func(chidx_chunk_record_t * record) {
    g_free(record);
}


static void parse_chidx_hdrv0(int chidx_fd, gchar *chidx_filename, chidx_hdr_t * v2hdr, chidx_hdr2_t ** v2hdr2p) {   // reads v0/v1 chidx file format and returns headers in v2 format
    chidx_hdr_v0_t v0hdr;
    int siglen = sizeof(v2hdr->signature);
    if (lseek(chidx_fd, siglen, SEEK_SET) < 0) {
        g_printerr("seek in v0 .chidx %s: %s\n", chidx_filename, g_strerror(errno));
        exit(11);
    }
    ssize_t v0hdrsize = sizeof(chidx_hdr_v0_t);
    ssize_t ret = read(chidx_fd, &v0hdr, v0hdrsize);
    if (ret < 0) {
        g_printerr("read error in v0 index file '%s' during header read: %s\n", chidx_filename, g_strerror(errno));
        exit(11);
    } else if (ret == 0) {
        g_printerr("read error in v0 index file '%s' during header read: EOF\n", chidx_filename);
        exit(11);
    } else if (ret != v0hdrsize) {
        g_printerr("read error in v0 index file '%s' during header read: short read\n", chidx_filename);
        exit(11);
    }

    v2hdr->formatversion     = g_ntohs(v0hdr.formatversion);
    v2hdr->winsize           = g_ntohl(v0hdr.winsize);
    v2hdr->chunkmask         = g_ntohl(v0hdr.chunkmask);
    v2hdr->minchunksize      = g_ntohl(v0hdr.minchunksize);
    v2hdr->fullfilehash_type = IMIDJ_HASH_MD5;
    v2hdr->fullfilehash_len  = hashsize_from_hashtype(IMIDJ_HASH_MD5);
    v2hdr->chunkhash_type    = IMIDJ_HASH_MD5;
    v2hdr->chunkhash_len     = hashsize_from_hashtype(IMIDJ_HASH_MD5);
    memset(v2hdr->reserved, 0x0, sizeof(v2hdr->reserved)); // zero out reserved

    if(opt_verbose) {
        g_print("headerinfo: formatversion=%d winsize=0x%04x chunkmask=0x%04x minchunksize=%d\n"
                "            filehashtype=%s filehashlen=%d chunkhashtype=%s chunkhashlen=%d",
                v2hdr->formatversion,
                v2hdr->winsize,
                v2hdr->chunkmask,
                v2hdr->minchunksize,
                hashname_from_hashtype(v2hdr->fullfilehash_type),
                v2hdr->fullfilehash_len,
                hashname_from_hashtype(v2hdr->chunkhash_type),
                v2hdr->chunkhash_len
            );
    }

    /* allocate space for a v2 style extended header aka hdr2 */
    ssize_t v2hdr2size = sizeof(chidx_hdr2_t) + v2hdr->fullfilehash_len;
    chidx_hdr2_t * v2hdr2 = g_malloc(v2hdr2size); // has a flexible array member
    /* stick the v0 MD5 full file checksum into hdr2 */
    memcpy(v2hdr2->fullfilehash, &(v0hdr.fullfilehash), hashsize_from_hashtype(IMIDJ_HASH_MD5));
    if (v2hdr2 == NULL) {
        g_printerr("memory allocation for file header failed '%s' during header read: %s\n", chidx_filename, g_strerror(errno));
        exit(9);
    }
    *v2hdr2p = v2hdr2; /* free'd by caller of parse_chidx() */
    return;
}

static void parse_chidx_hdrv2(int chidx_fd, gchar *chidx_filename, chidx_hdr_t * hdr, chidx_hdr2_t ** hdr2p) {
    // most primary header work has already been done by parse_chidx()
    if(opt_verbose) {
        g_print("headerinfo: formatversion=%d winsize=0x%04x chunkmask=0x%04x minchunksize=%d\n"
                "            filehashtype=%s filehashlen=%d chunkhashtype=%s chunkhashlen=%d",
                hdr->formatversion,
                hdr->winsize,
                hdr->chunkmask,
                hdr->minchunksize,
                hashname_from_hashtype(hdr->fullfilehash_type),
                hdr->fullfilehash_len,
                hashname_from_hashtype(hdr->chunkhash_type),
                hdr->chunkhash_len
            );
    }

    /* read fullfile checksum aka hdr2 */
    ssize_t hdr2size = sizeof(chidx_hdr2_t) + hdr->fullfilehash_len;
    chidx_hdr2_t * hdr2 = g_malloc(hdr2size); // has a flexible array member
    if (hdr2 == NULL) {
        g_printerr("memory allocation for file header failed '%s' during header read: %s\n", chidx_filename, g_strerror(errno));
        exit(9);
    }
    *hdr2p = hdr2; /* free'd by caller of parse_chidx() */

    ssize_t ret = read(chidx_fd, hdr2, hdr2size);
    if (ret < 0) {
        g_printerr("read error in index file '%s' during extheader read: %s\n", chidx_filename, g_strerror(errno));
        exit(11);
    } else if (ret == 0) {
        g_printerr("read error in index file '%s' during extheader read: EOF\n", chidx_filename);
        exit(11);
    } else if (ret != hdr2size) {
        g_printerr("read error in index file '%s' during extheader read: short read\n", chidx_filename);
        exit(11);
    }
    return;
}

gboolean parse_chidx(gchar *chidx_filename, chidx_hdr_t * hdr, chidx_hdr2_t ** hdr2p, GPtrArray *chunk_list) {
    if(opt_verbose) { g_print("loading chidx '%s'...\n", chidx_filename); }
    int tchidx = g_open(chidx_filename, O_RDONLY);
    if (tchidx < 0) {
        g_printerr("Cannot open chunk index file '%s': %s\n", chidx_filename, g_strerror(errno));
        exit(10);
    }

    /* read hdr0 */
    ssize_t hdrsize = sizeof(chidx_hdr_t);
    ssize_t ret = read(tchidx, hdr, hdrsize);
    if (ret < 0) {
        g_printerr("read error in index file '%s' during header read: %s\n", chidx_filename, g_strerror(errno));
        exit(11);
    } else if (ret == 0) {
        g_printerr("read error in index file '%s' during header read: EOF\n", chidx_filename);
        exit(11);
    } else if (ret != hdrsize) {
        g_printerr("read error in index file '%s' during header read: short read\n", chidx_filename);
        exit(11);
    }

    /* check file magic */
    gchar signature[] = "CHiDX";
    if (memcmp(hdr, signature, 5) != 0) {
        g_printerr("bad signature in '%s'\n", chidx_filename);
        exit(12);
    }
    if(opt_verbose) { g_print("signature check: ok\n"); }

    /* network to host byte order */
    hdr->formatversion    = g_ntohs(hdr->formatversion);
    hdr->winsize          = g_ntohl(hdr->winsize);
    hdr->chunkmask        = g_ntohl(hdr->chunkmask);
    hdr->minchunksize     = g_ntohl(hdr->minchunksize);
    hdr->fullfilehash_len = g_ntohs(hdr->fullfilehash_len);
    hdr->chunkhash_len    = g_ntohs(hdr->chunkhash_len);

    /* determine chidx file format version before accessing more fields */
    switch(hdr->formatversion) {
        case 0: // fallthrough to 1
        case 1: {
            /* read v0 format and convert to v2 header structs in RAM */
            parse_chidx_hdrv0(tchidx, chidx_filename, hdr, hdr2p);
            break;
        }
        case 2:{
            parse_chidx_hdrv2(tchidx, chidx_filename, hdr, hdr2p);
            break;
        }
        default: {
            g_printerr("This version cannot process chunk index files with version '%d' ('%s')\n", hdr->formatversion, chidx_filename);
            exit(14);
        }
    }

    chidx_hdr2_t * hdr2 = *hdr2p; /* hdr2 was allocated by version-specific header parser */

    if (opt_verbose) {
        char * hexdigest = hexlify_digest(hdr->fullfilehash_type, hdr2->fullfilehash);
        if (hexdigest==NULL) {
            g_printerr("memory allocation failed (at %s:%d): %s\n", __FILE__, __LINE__, g_strerror(errno));
            exit(9);
        }
        g_print("headerinfo: image checksum=%s\n", hexdigest);
        free(hexdigest);
    }

    /* process file payload: chunk records, handles both v0 and v2 */
    gint i = 0;
    gint offset = 0;
    while(1) {
        /* the chunk hash type in hdr->chunkhash_type determines the format & size */
        ssize_t record_read_size = sizeof(chidx_chunk_file_record_t) + hdr->chunkhash_len;
        chidx_chunk_file_record_t * filerecord = g_malloc(record_read_size); // has a flexible array member
        chidx_chunk_record_t * record = g_malloc(sizeof(chidx_chunk_record_t) + hdr->chunkhash_len); // has a flexible array member

        record->num = i;
        record->offset = offset;

        if (opt_verbose && i==0) { g_print("chunk record read size: %zd \n", record_read_size);}

        ret = read(tchidx, filerecord, record_read_size);
        if (ret < 0) {
            g_printerr("read error in index file '%s' at %d: %s\n", chidx_filename, offset, g_strerror(errno));
            exit(15);
        } else if (ret == 0) /* EOF */ {
            g_free(record);
            g_free(filerecord);
            break;
        } else if (ret < record_read_size) /* file truncated */ {
            g_printerr("read error in index file '%s' at %d: incomplete chunk record\n", chidx_filename, offset);
            exit(15);
        }
        record->l = g_ntohl(filerecord->l);
        memcpy(record->chunkhash, filerecord->chunkhash, hdr->chunkhash_len);
        if (opt_verbose) {
            char * hexdigest = hexlify_digest(hdr->chunkhash_type, record->chunkhash);
            if (hexdigest==NULL) {
                g_printerr("memory allocation failed (at %s:%d): %s\n", __FILE__, __LINE__, g_strerror(errno));
                exit(9);
            }
            g_print("Read Chunk Index [%d] size=%d hash=%s\n", i, record->l, hexdigest);
            free(hexdigest);
        }
        i += 1;
        offset += record->l;
        g_ptr_array_add(chunk_list, (gpointer)record);
        g_free(filerecord);
    }
    if(opt_verbose) {g_print("chunk index file (%s) contains references to %d chunks\n", chidx_filename, i);}
    g_close(tchidx, NULL);
    return TRUE;
}


static int write_chunkindex_header(int fd, uint8_t * filehash) {
    chidx_hdr_t hdr;
    memcpy(hdr.signature, "CHiDX", 5);
    hdr.formatversion       = g_htons(FORMATVERSION);
    hdr.winsize             = g_htonl(WINSIZE);
    hdr.chunkmask           = g_htonl(CHUNKMASK);
    hdr.minchunksize        = g_htonl(MINCHUNKSIZE);
    hdr.fullfilehash_type   = DEFAULT_WHOLEFILE_HASH;
    hdr.fullfilehash_len    = g_htons(hashsize_from_hashtype(hdr.fullfilehash_type));
    hdr.chunkhash_type      = DEFAULT_CHUNK_HASH;
    hdr.chunkhash_len       = g_htons(hashsize_from_hashtype(hdr.chunkhash_type));
    memset(hdr.reserved, 0x0, sizeof(hdr.reserved));

    if (write(fd, &hdr, sizeof(chidx_hdr_t)) <= 0) {
        g_printerr("error while trying to write chunk index file header: %s", g_strerror(errno));
        exit(40);
    }

    ssize_t filehashsize = hashsize_from_hashtype(hdr.fullfilehash_type);
    ssize_t hdr2size = sizeof(chidx_hdr2_t) + filehashsize;
    chidx_hdr2_t * hdr2 = g_malloc(hdr2size); // has a flexible array member
    if (hdr2 == NULL) {
        g_printerr("memory allocation for file header failed during header write: %s\n", g_strerror(errno));
        exit(9);
    }

    hdr2->undefined = 0;
    memcpy(hdr2->fullfilehash, filehash, filehashsize);
    if (write(fd, hdr2, hdr2size) <= 0) {
        g_printerr("error while trying to write chunk index file header: %s", g_strerror(errno));
        exit(40);
    }
    g_free(hdr2);
    return 0;
}


 int index_a_file(char * filename, hash_type_t htype_chunks, GPtrArray *chunk_records, GHashTable * chunk_refcnt_table) /* chunk_refcnt_table is optional, use NULL to ignore */
{
    if (chunk_records == NULL) {
        g_printerr("chunk record table should not be NULL in %s:%d\n", __FILE__, __LINE__);
        exit(110);
    }

    /* open image */
    int fd = g_open(filename, O_RDONLY);
    if (fd < 0) {
        g_printerr("Cannot open image file for indexing '%s': %s\n", filename, g_strerror(errno));
        exit(111);
    }
    int i = 0;
    long long offset = 0;
    uint32_t seed = 0;
    Chunker * chunker = chunker_init(WINSIZE, CHUNKMASK, MINCHUNKSIZE, seed & 0xffffffff);
    chunker_set_fd(chunker, fd);

    raw_chunk_w_size_t chunk;
    g_assert(chunk_records != NULL);

    while( 1 ) {
        uint16_t chunkhash_len = hashsize_from_hashtype(htype_chunks);
        //ssize_t record_write_size = sizeof(chidx_chunk_file_record_t) + chunkhash_len;
        //chidx_chunk_file_record_t * filerecord = g_malloc(record_write_size); // has a flexible array member
        chidx_chunk_record_t * record = g_malloc(sizeof(chidx_chunk_record_t) + chunkhash_len); // has a flexible array member

        chunk = chunker_process(chunker);
        if (chunk.error != CHUNKER_ERROR_NONE) {
            g_printerr("chunker error %d occurred\n", chunk.error);
            exit(112);
        } else if (chunk.data == NULL) {
            g_free(record);
            break;
        }

        /* calculate chunk digest with designated hash */
        uint8_t * digest = calculate_digest(htype_chunks, chunk.data, chunk.len);
        gchar * hexdigest = hexlify_digest(htype_chunks, digest);

        if (chunk_refcnt_table != NULL) {
            GBytes * gb_key = g_bytes_new(digest, chunkhash_len);
            if (g_hash_table_contains(chunk_refcnt_table, gb_key)) {
                /* increment by 1 */
                long * val = (long *)(g_hash_table_lookup(chunk_refcnt_table, gb_key));
                (*val) += 1;
                g_bytes_unref(gb_key);
            } else {
                long * val = malloc(sizeof(long));
                *val = 1;
                g_hash_table_insert(chunk_refcnt_table, gb_key, val);
            }
        }
        if(opt_verbose) { g_print("%s\n", hexdigest); }
        g_free(hexdigest);

        record->num = i;
        record->offset = offset;
        record->l = chunk.len;
        memcpy(record->chunkhash, digest, chunkhash_len);
        g_free(digest);
        /* insert chunk record into list */
        g_ptr_array_add(chunk_records, (gpointer)record);
        i += 1;
        offset += chunk.len;
        if (chunk.data != NULL) {
            free(chunk.data);
        }
    }
    chunker_free(chunker);
    g_close(fd, NULL);
    return(0);
}

static int write_chidx(char * idx_filename, char * img_filename, uint8_t * wholefile_digest, GPtrArray *chunk_records) /* img_filename may be NULL if indexer_index_only is false */
{
    g_print("writing chunkindex to '%s'\n", idx_filename);
    g_assert(idx_filename != NULL);
    g_assert(wholefile_digest != NULL);
    g_assert(chunk_records != NULL);

    if (img_filename == NULL && ! indexer_index_only) {
        g_printerr("idx_filename is NULL at %s:%d\n", __FILE__, __LINE__);
        exit(34);
    }
    int fd = g_open(idx_filename, O_CREAT|O_WRONLY|O_TRUNC, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
    if (fd < 0) {
        g_printerr("Cannot create chunk index file '%s': %s\n", idx_filename, g_strerror(errno));
        exit(35);
    }
    write_chunkindex_header(fd, wholefile_digest);

    /* iter over chunk records */
    for (unsigned int i = 0; i < chunk_records->len; i++)
    {
        chidx_chunk_record_t * record = g_ptr_array_index(chunk_records, i);
        uint16_t chunkhash_len = hashsize_from_hashtype(DEFAULT_CHUNK_HASH);
        ssize_t record_write_size = sizeof(chidx_chunk_file_record_t) + chunkhash_len;
        chidx_chunk_file_record_t * filerecord = g_malloc(record_write_size); // has a flexible array member
        filerecord->l = g_htonl(record->l);
        memcpy(filerecord->chunkhash, record->chunkhash, chunkhash_len);
        if (write(fd, filerecord, sizeof(chidx_chunk_file_record_t) + chunkhash_len) <= 0) { /* chunk checksum */
            g_printerr("error while trying to write chunk index file chunk record: %s", g_strerror(errno));
            exit(37);
        }
        g_free(filerecord);
    }
    g_close(fd, NULL);
    return(0);
}

static int indexer_main(void)
{
    char * image_path = realpath(indexer_image, NULL);
    if (image_path == NULL) {
        g_printerr("image_path is NULL: %s\n", g_strerror(errno));
        exit(33);
    }
    gchar * image_dir = g_path_get_dirname(image_path);
    gchar * image_fname = g_path_get_basename(image_path);

    if (g_mkdir_with_parents(indexer_outdir, 0755) < 0) {
        g_printerr("Cannot create output directory for chunks and index file '%s': %s\n", indexer_outdir, g_strerror(errno));
        exit(34);
    }

    char * outputdir = realpath(indexer_outdir, NULL);
    if (outputdir == NULL) {
        g_printerr("outputdir is NULL: %s\n", g_strerror(errno));
        exit(33);
    }
    char * index_path = g_strdup_printf("%s/%s%s", outputdir, image_fname, ".chidx");

    if (! g_file_test(image_path, (G_FILE_TEST_EXISTS | G_FILE_TEST_IS_REGULAR))) {
        g_printerr("image file not found: '%s'\n", image_path);
        exit(30);
    }
    if (g_file_test(index_path, G_FILE_TEST_EXISTS) && ! indexer_force_overwrite) {
        g_printerr("index file '%s' already exists\n", index_path);
        exit(31);
    }

    /* open image */
    int fd = g_open(image_path, O_RDONLY);
    if (fd < 0) {
        g_printerr("Cannot open image file '%s': %s\n", image_path, g_strerror(errno));
        exit(32);
    }

    /* checksum of whole file */
    uint8_t * wholefile_digest = calculate_digest_file(DEFAULT_WHOLEFILE_HASH, image_path);
    g_print("indexing...\n");
    GPtrArray * chunk_records = g_ptr_array_new_with_free_func((GDestroyNotify)chunk_record_free_func);
    GHashTable * chunk_refcnt_table = g_hash_table_new_full(g_bytes_hash, g_bytes_equal, (GDestroyNotify)g_bytes_unref, (GDestroyNotify)free);
    index_a_file(image_path, DEFAULT_CHUNK_HASH, chunk_records, chunk_refcnt_table);

    write_chidx(index_path, image_path, wholefile_digest, chunk_records);
    if (! indexer_index_only) {
        write_chblos(image_path, outputdir, chunk_records);
    }

    /* iter over chunk_refcnt_table to count duplicates */
    int total_chunks = 0;
    int unique_chunks = 0;
    GHashTableIter iter;
    gpointer value;
    g_hash_table_iter_init(&iter, chunk_refcnt_table);
    while (g_hash_table_iter_next(&iter, NULL,  &value)) {
        long * val = (long *)value;
        total_chunks += (*val);
        unique_chunks += 1;
        if(opt_verbose) { g_print("total chunks now: %d   unique now %d\n", total_chunks, unique_chunks); }
    }
    g_print("chunks total: %d  unique: %d\n", total_chunks, unique_chunks);

    g_print("checksum of image file: ");
    for(int i = 0; i < hashsize_from_hashtype(DEFAULT_WHOLEFILE_HASH); i++) {
        g_print("%02x", wholefile_digest[i]);
    }
    g_print("\n");

    /* cleanup */
    g_close(fd, NULL);
    g_hash_table_destroy(chunk_refcnt_table);
    g_ptr_array_free(chunk_records, TRUE);
    free(wholefile_digest);
    g_free(index_path);
    free(outputdir);
    g_free(image_fname);
    g_free(image_dir);
    free(image_path);

    return 0;
}


int index_args(int argc, char ** argv) {
    GOptionContext * context = g_option_context_new ("index <IMAGE> <OUTDIR>");
    g_option_context_set_help_enabled(context, TRUE);
    g_option_context_add_main_entries(context, indexer_entries, NULL);
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

    if (indexer_rest == NULL || indexer_rest[0] == NULL)
    {
        g_printerr("%s: missing argument: IMAGE\n", g_get_prgname());
        return(1);
    }
    if (indexer_rest[1] == NULL || indexer_rest[2] != NULL)
    {
        g_printerr("%s: missing argument: OUTDIR\n", g_get_prgname());
        return(1);
    }
    if (indexer_rest[2] != NULL)
    {
        g_printerr("%s: too many arguments\n", g_get_prgname());
        return(1);
    }

    indexer_image = g_strdup (indexer_rest[0]);
    indexer_outdir = g_strdup (indexer_rest[1]);
    int ret = indexer_main();
    g_free(indexer_outdir);
    g_free(indexer_image);
    return ret;
}

