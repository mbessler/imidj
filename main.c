/*
 * This file is part of the IMIDJ - IMage Incremental Deltafragment Joiner
 * (https://github.com/mbessler/imidj)
 *
 * Copyright (c) 2019 Manuel Bessler
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
#include <limits.h>
#include <stdlib.h>

/* glib includes */
#include <glib.h>
#include <gmodule.h>
#include <glib/gi18n.h>
#include <glib/gstdio.h>
#include <glib/gprintf.h>

/* libcrypto includes */
#include <openssl/md5.h>

/* libcurl includes */
#include <curl/curl.h>

#ifdef LZMA
/* lzma */
#include <lzma.h>
#endif /* LZMA */

#include "chunker.h"

#define VERSION "0.0.0"

#define MAX_REF_IMAGES (8)

#define FORMATVERSION (0)
#define WINSIZE (0xfff)
#define CHUNKMASK (0xffff)
#define MINCHUNKSIZE (1024)


typedef enum {
    IMIDJ_MODE_HELP = 0,
    IMIDJ_MODE_INDEXER = 1,
    IMIDJ_MODE_PATCHER = 2,
    IMIDJ_MODE_ANALYZER = 3,
    IMIDJ_MODE_VERSION = 4,
} imidj_mode_t;

typedef gboolean (*mode_dispatch_handler_t)(int argc, char **argv);

typedef struct __attribute__((packed/*, aligned(4)*/)) {
    uint16_t formatversion; //2
    uint32_t winsize;  //4
    uint32_t chunkmask;  //4
    uint32_t minchunksize; //4
    uint8_t fullfilehash[16];  //16
    // total: 30bytes
} chidx_header_t; /* header block of chunk index file, minus the file signature itself */

typedef struct __attribute__((packed /*, aligned(4)*/)) {
    uint32_t l;
    uint8_t chunkhash[16];
} chidx_chunk_file_record_t;

typedef struct {
    chidx_chunk_file_record_t chunk_record;
    uint32_t num;
    uint64_t offset;
} chidx_chunk_record_t;

typedef struct {
    unsigned int chunks_fetched;
    unsigned int chunks_local;
    size_t bytes_fetched;
    size_t bytes_fetched_actual;
    size_t bytes_local;

    unsigned int chunks_already_present;
    size_t bytes_already_present;
} imidj_patch_stats_t;

imidj_patch_stats_t patch_stats = {
    .chunks_fetched = 0,
    .chunks_local = 0,
    .bytes_fetched = 0,
    .bytes_fetched_actual = 0,
    .bytes_local = 0,
    .chunks_already_present = 0,
    .bytes_already_present = 0 };


static gboolean indexer_index_only = FALSE;
static gboolean indexer_force_overwrite = FALSE;
static gchar** indexer_rest = NULL;
static gchar * indexer_image = NULL;
static gchar * indexer_outdir = NULL;

static gchar* patcher_index_file = NULL;
static gchar* patcher_out_img = NULL;
static gchar* patcher_url = NULL;
static gboolean patcher_force_overwrite = FALSE;
static gchar** patcher_reference_index_array = NULL;
static gchar** patcher_reference_image_array = NULL;
static gchar* patcher_stats_out = NULL;
static gchar** patcher_rest = NULL;
static gboolean url_is_local = FALSE;

static gboolean opt_verbose = FALSE;
static gboolean opt_version = FALSE;
CURL * ceh = NULL;


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

GOptionEntry patcher_entries[] = {
    /* imidj patch --force-overwrite --stats-out STATSFILE --url URL -r img1.chidx -R img1.img -r img2.chidx -R img2.img IMAGE INDEX */

    /* required args */
    {"url", 'u', 0, G_OPTION_ARG_STRING, &patcher_url, "Base URL of chunk server. Accepts http/https/ftp or local paths. Do not include the trailing 'chunks/' component", "URL"},

    /* optional args */
    {"force-overwrite", '\0', 0, G_OPTION_ARG_NONE, &patcher_force_overwrite, "Force overwrite output image file if it already exists (no incremental upgrade)", NULL},
    {"stats-out", '\0', 0, G_OPTION_ARG_FILENAME, &patcher_stats_out, "Output JSON statistics to STATSFILE", "STATSFILE"},
    {"reference-index", 'r', 0, G_OPTION_ARG_FILENAME_ARRAY, &patcher_reference_index_array, "Index file for reference image (requires matching '-R'; can be specified zero or more times)", "INDEXFILE"},
    {"reference-image", 'R', 0, G_OPTION_ARG_FILENAME_ARRAY, &patcher_reference_image_array, "Existing image file as reference (requires matching '-r'; can be specified zero or more times) ", "IMAGEFILE"},
    {"verbose", 'v', 0, G_OPTION_ARG_NONE, &opt_verbose, "Increase output verbosity", NULL },
    /* general */
    {"version", 'V', 0, G_OPTION_ARG_NONE, &opt_version, "Show version information", NULL },
    /* remaining args */
    {G_OPTION_REMAINING, 0, 0, G_OPTION_ARG_FILENAME_ARRAY, &patcher_rest, NULL, NULL},
    {0}
};

static void usage(GOptionContext *context) {
    g_autofree gchar *text = NULL;
    text = g_option_context_get_help(context, FALSE, NULL);
    g_print("Copyright (C) 2019 by Manuel Bessler\n" \
            "License: GPLv2\n"                       \
            "\n"                                     \
            "%s", text);
}

static gboolean version_main(int argc, char **argv)
{
    (void) argc;
    (void) argv;
    g_print(VERSION "\n");
    exit(1);
}

static gchar * hexlify_md5(uint8_t digest[16]) {
    gchar * hexdigest = calloc(1, MD5_DIGEST_LENGTH*2+1);
    if (hexdigest == NULL) {
        g_printerr("memory allocation failed: %s\n", g_strerror(errno));
        exit(105);
    }
    for(int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        gchar hexdigit[3];
        g_snprintf(hexdigit, 3, "%02x", digest[i]);
        g_strlcat(hexdigest, hexdigit, MD5_DIGEST_LENGTH*2+1);
    }
    return(hexdigest);
}

static gboolean parse_chidx(gchar *chidx_filename, chidx_header_t * hdr, GPtrArray *chunk_list) {
    if(opt_verbose) { g_print("loading chidx '%s'...\n", chidx_filename); }
    int tchidx = g_open(chidx_filename, O_RDONLY);
    if (tchidx < 0) {
        g_printerr("Cannot open chunk index file '%s': %s\n", chidx_filename, g_strerror(errno));
        exit(10);
    }
    /* check file magic */
    int siglen = strlen("CHiDX");
    char buf[siglen+1];
    ssize_t ret = read(tchidx, buf, siglen);
    if (ret < 0) {
        g_printerr("read error in index file '%s' during signature read: %s\n", chidx_filename, g_strerror(errno));
        exit(11);
    } else if (ret == 0) {
        g_printerr("read error in index file '%s' during signature read: EOF\n", chidx_filename);
        exit(11);
    }
    buf[siglen] = '\0';
    if (g_strcmp0(buf, "CHiDX") != 0) {
        g_printerr("bad signature in '%s'\n", chidx_filename);
        exit(12);
    }
    if(opt_verbose) { g_print("signature check: ok\n"); }

    ret = read(tchidx, hdr, sizeof(chidx_header_t));
    if(opt_verbose) { g_print("     -> read header (%zd bytes) sizeof=%zd\n", ret, sizeof(chidx_header_t));}
    if (ret < 0) {
        g_printerr("read error in index file '%s' during header read: %s\n", chidx_filename, g_strerror(errno));
        exit(13);
    } else if (ret == 0) {
        g_printerr("read error in index file '%s' during header read: EOF\n", chidx_filename);
        exit(13);
    }

    hdr->formatversion = g_ntohs(hdr->formatversion);
    hdr->winsize = g_ntohl(hdr->winsize);
    hdr->chunkmask = g_ntohl(hdr->chunkmask);
    hdr->minchunksize = g_ntohl(hdr->minchunksize);
    if(opt_verbose) {
        g_print("headerinfo: formatversion=%d winsize=0x%04x chunkmask=0x%04x minchunksize=%d\n",
                hdr->formatversion,
                hdr->winsize,
                hdr->chunkmask,
                hdr->minchunksize);
    }

    if (hdr->formatversion > 1) {
        g_printerr("This version cannot process chunk index files with version '%d' ('%s')\n", hdr->formatversion, chidx_filename);
        exit(14);
    }
    if (opt_verbose) {
        char * hexdigest = hexlify_md5(hdr->fullfilehash);
        if (hexdigest==NULL) {
            g_printerr("memory allocation error at %s:%d\n", __FILE__, __LINE__);
            exit(9);
        }
        g_print("headerinfo: image checksum=%s\n", hexdigest);
        g_free(hexdigest);
    }

    gint i = 0;
    gint offset = 0;
    while(1) {
        chidx_chunk_record_t * record = g_new(chidx_chunk_record_t, 1);
        record->num = i;
        record->offset = offset;
        ssize_t record_read_size = sizeof(record->chunk_record);
        if (opt_verbose && i==0) { g_print("chunk record read size: %zd \n", record_read_size);}
        ret = read(tchidx, &(record->chunk_record), record_read_size);
        if (ret < 0) {
            g_printerr("read error in index file '%s' at %d: %s\n", chidx_filename, offset, g_strerror(errno));
            exit(15);
        } else if (ret == 0) /* EOF */ {
            break;
        } else if (ret < record_read_size) /* file truncated */ {
            g_printerr("read error in index file '%s' at %d: incomplete chunk record\n", chidx_filename, offset);
            exit(15);
        }
        record->chunk_record.l = g_ntohl(record->chunk_record.l);

        if (opt_verbose) {
            char * hexdigest = hexlify_md5(record->chunk_record.chunkhash);
            if (hexdigest==NULL) {
                g_printerr("memory allocation error at %s:%d\n", __FILE__, __LINE__);
                exit(9);
            }
            g_print("Read Chunk Index [%d] size=%d hash=%s\n", i, record->chunk_record.l, hexdigest);
            g_free(hexdigest);
        }
        
        i += 1;
        offset += record->chunk_record.l;
        
        g_ptr_array_add(chunk_list, (gpointer)record);
    }
    g_print("chunk index file (%s) contains references to %d chunks\n", chidx_filename, i);
    g_close(tchidx, NULL);
    return TRUE;
}


static int write_chunkindex_header(int fd, uint8_t * filehash) {
    if (write(fd, "CHiDX", 5) <= 0) {
        g_printerr("error while trying to write chunk index file header: %s", g_strerror(errno));
        exit(40);
    }
    uint16_t vs = g_htons(FORMATVERSION);
    if (write(fd, &vs, 2) <= 0) {
        g_printerr("error while trying to write chunk index file header: %s", g_strerror(errno));
        exit(40);
    }
    uint32_t vl = g_htonl(WINSIZE);
    if (write(fd, &vl, 4) <= 0) {
        g_printerr("error while trying to write chunk index file header: %s", g_strerror(errno));
        exit(40);
    }
    vl = g_htonl(CHUNKMASK);
    if (write(fd, &vl, 4) <= 0) {
        g_printerr("error while trying to write chunk index file header: %s", g_strerror(errno));
        exit(40);
    }
    vl = g_htonl(MINCHUNKSIZE);
    if (write(fd, &vl, 4) <= 0) {
        g_printerr("error while trying to write chunk index file header: %s", g_strerror(errno));
        exit(40);
    }
    if (write(fd, filehash, MD5_DIGEST_LENGTH) <= 0) {
        g_printerr("error while trying to write chunk index file header: %s", g_strerror(errno));
        exit(40);
    }
    return 0;
}

#ifdef LZMA
static gboolean decompress(int infd, int outfd, int * ret_compressed_size) {
    lzma_stream lz_strm = LZMA_STREAM_INIT;
    lzma_ret lz_ret = lzma_stream_decoder(&lz_strm, UINT64_MAX, LZMA_TELL_ANY_CHECK | LZMA_TELL_NO_CHECK);
    if (lz_ret != LZMA_OK) {
        switch (lz_ret) {
        case LZMA_MEM_ERROR:
            g_printerr("Memory allocation failed\n");
            break;
        case LZMA_OPTIONS_ERROR:
            g_printerr("Specified preset is not supported\n");
            break;
        default:
            g_printerr("Error, lzma_stream_decoder init failed with %u\n", lz_ret);
            break;
        }
        exit(55);
    }

    lzma_action action = LZMA_RUN;

    uint8_t inbuf[1024*128];
    uint8_t outbuf[1024*128];
    lz_strm.next_in = NULL;
    lz_strm.avail_in = 0;
    lz_strm.next_out = outbuf;
    lz_strm.avail_out = sizeof(outbuf);
    gboolean ineof = FALSE;
    if (ret_compressed_size) {
        *ret_compressed_size = 0;
    }

    while (1) {
        if (lz_strm.avail_in == 0 && ! ineof) {
            lz_strm.next_in = inbuf;
            ssize_t num_read = read(infd, inbuf, sizeof(inbuf));
            if (num_read == 0) {
                ineof = TRUE;
            } else if (num_read < 0) {
                g_printerr("error reading from chblo file: %s\n", g_strerror(errno));
                exit(56);
            }
            lz_strm.avail_in = num_read;
            if (ret_compressed_size) {
                *ret_compressed_size += num_read;
            }

            // if input EOF, set LZMA_FINISH
            if (ineof){
                action = LZMA_FINISH;
            }
        }

        lz_ret = lzma_code(&lz_strm, action);
        if (lz_strm.avail_out == 0 || lz_ret == LZMA_STREAM_END) {
            ssize_t write_size = sizeof(outbuf) - lz_strm.avail_out;
            ssize_t num_written = write(outfd, outbuf, write_size);
            if (num_written < 0) {
                g_printerr("error writing decompressed chunk block to image: %s\n", g_strerror(errno));
                exit(57);
            } else if (num_written != write_size) {
                g_printerr("error short write while writing decompressed chunk block to image, expected: %zd, wrote: %zd\n", write_size, num_written);
                exit(57);
            }

            lz_strm.next_out = outbuf;
            lz_strm.avail_out = sizeof(outbuf);
        }

        if (lz_ret == LZMA_STREAM_END){
            break;
        }
        if (lz_ret != LZMA_OK && lz_ret != LZMA_GET_CHECK && lz_ret != LZMA_NO_CHECK) {
            switch (lz_ret) {
            case LZMA_MEM_ERROR:
                g_printerr("Memory allocation failed\n");
                break;
            case LZMA_OPTIONS_ERROR:
                g_printerr("Specified preset is not supported\n");
                break;
            case LZMA_FORMAT_ERROR:
                g_printerr("The input is not in the .xz format\n");
                break;
            case LZMA_DATA_ERROR:
                g_printerr("Compressed file is corrupt\n");
                break;
            case LZMA_BUF_ERROR:
                g_printerr("Compressed file is truncated or otherwise corrupt\n");
                break;
                g_printerr("\n");
                break;
            default:
                g_printerr("lzma_code failed with %u\n", lz_ret);
                break;
            }
            exit(56);
        }
    }
    lzma_end(&lz_strm);
    return TRUE;
}


static size_t compress(int outfd, uint8_t * data, int len) {
    uint32_t lz_preset = 6; // 6 since any higher than 6 requires a lot more memory during decompress on the target
    lzma_stream lz_strm = LZMA_STREAM_INIT;
    lzma_ret lz_ret;
    if ((lz_ret = lzma_easy_encoder(&lz_strm, lz_preset, LZMA_CHECK_CRC64/*-1 in py impl */)) != LZMA_OK) {
        switch (lz_ret) {
        case LZMA_MEM_ERROR:
            g_printerr("Memory allocation failed\n");
            break;
        case LZMA_OPTIONS_ERROR:
            g_printerr("Specified preset is not supported\n");
            break;
        case LZMA_UNSUPPORTED_CHECK:
            g_printerr("Specified integrity check is not supported\n");
            break;
        default:
            g_printerr("lzma init failed with %u\n", lz_ret);
            break;
        }
        exit(50);
    }

    lzma_action action = LZMA_RUN;
    uint8_t outbuf[1024*128];
    lz_strm.next_in = data;
    lz_strm.avail_in = len;
    lz_strm.next_out = outbuf;
    lz_strm.avail_out = sizeof(outbuf);

    size_t total_written = 0;
    while (1) {
        action = LZMA_FINISH; /* since we're giving it the whole buffer */
        lz_ret = lzma_code(&lz_strm, action);
        if (lz_strm.avail_out == 0 || lz_ret == LZMA_STREAM_END) {
            ssize_t write_size = sizeof(outbuf) - lz_strm.avail_out;
            if (write(outfd, outbuf, write_size) != write_size) {
                g_printerr("error writing compressed chunk: %s\n", g_strerror(errno));
                exit(52);
            }
            total_written += write_size;
            // Reset next_out and avail_out.
            lz_strm.next_out = outbuf;
            lz_strm.avail_out = sizeof(outbuf);
        }

        if (lz_ret == LZMA_STREAM_END)
            break;
        if (lz_ret != LZMA_OK) {
            switch (lz_ret) {
            case LZMA_MEM_ERROR:
                g_printerr("Memory allocation failed\n");
                break;
            case LZMA_DATA_ERROR:
                g_printerr("File size limits exceeded\n");
                break;
            default:
                g_printerr("lzma_code failed with %u\n", lz_ret);
                break;
            }
            exit(53);
        }
    }
    lzma_end(&lz_strm);
    return total_written;
}
#endif /* LZMA */

static uint8_t * whole_file_checksum(char * filename) {
    /* checksum whole file */
    int fd = g_open(filename, O_RDONLY);
    if (fd < 0) {
        g_printerr("cannot open file for checksumming '%s': %s\n", filename, g_strerror(errno));
        exit(102);
    }

    uint8_t * digest = malloc(MD5_DIGEST_LENGTH);
    if (digest == NULL) {
        g_printerr("memory allocation failed for file checksumming: %s\n", g_strerror(errno));
        exit(101);
    }
    MD5_CTX mdctx;
    MD5_Init(&mdctx);

    const size_t readsize = 256*1024;
    while (1) {
        uint8_t buf[readsize];
        ssize_t num_read = read(fd, buf, readsize);
        if (num_read < 0) {
            g_printerr("read error during checksumming file '%s': %s\n", filename, g_strerror(errno));
            exit(103);
        } else if (num_read == 0) { /* EOF */
            break;
        }
        MD5_Update (&mdctx, buf, num_read);
    }
    MD5_Final(digest, &mdctx);
    g_close(fd, NULL);
    return digest;
}

static int index_a_file(char * filename, GPtrArray *chunk_records, GHashTable * chunk_refcnt_table) /* chunk_refcnt_table is optional, use NULL to ignore */
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
        chidx_chunk_record_t * record = g_new(chidx_chunk_record_t, 1);

        chunk = chunker_process(chunker);
        if (chunk.error != CHUNKER_ERROR_NONE) {
            g_printerr("chunker error %d occurred\n", chunk.error);
            exit(112);
        } else if (chunk.data == NULL) {
            break;
        }

        // md5 hash the chunk
        uint8_t digest[MD5_DIGEST_LENGTH];
        MD5_CTX mdctx;
        MD5_Init(&mdctx);
        MD5_Update(&mdctx, chunk.data, chunk.len);
        MD5_Final(digest, &mdctx);

        gchar hexdigest[MD5_DIGEST_LENGTH*2+1] = { 0};
        for(int _i = 0; _i < MD5_DIGEST_LENGTH; _i++) {
            gchar hexdigit[3];
            g_snprintf(hexdigit, 3, "%02x", digest[_i]);
            g_strlcat(hexdigest, hexdigit, MD5_DIGEST_LENGTH*2+1);
        }
        g_print("%s\n", hexdigest);

        if (chunk_refcnt_table != NULL) {
            GBytes * gb_key = g_bytes_new(digest, MD5_DIGEST_LENGTH);
            if (g_hash_table_contains(chunk_refcnt_table, gb_key)) {
                /* increment by 1 */
                long * val = (long *)(g_hash_table_lookup(chunk_refcnt_table, gb_key));
                *val += 1;
                //g_hash_table_replace(chunk_refcnt_table, gb_key,
                //                     (void *)(
                //                         (long)(g_hash_table_lookup(chunk_refcnt_table, gb_key)) + 1
                //                         ));
            } else {
                long * val = malloc(sizeof(long));
                *val = 1;
                g_hash_table_insert(chunk_refcnt_table, gb_key, val);
            }
        }

        record->num = i;
        record->offset = offset;
        record->chunk_record.l = chunk.len;
        memcpy(record->chunk_record.chunkhash, digest, MD5_DIGEST_LENGTH);
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

static int write_chblos(char * img_filename, char * outputdir, GPtrArray *chunk_records)
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
        uint8_t * chunk_data = malloc(record->chunk_record.l);
        if (chunk_data == NULL) {
            g_printerr("memory allocation error at %s:%d\n", __FILE__, __LINE__);
            exit(9);
        }
        if (read(imgfd, chunk_data, record->chunk_record.l) != (ssize_t)record->chunk_record.l) {
            g_printerr("could not read chunk from image file for writing to chunk store '%s': %s\n", img_filename, g_strerror(errno));
            exit(41);
        }

        /* write chunk to chunkstore */
        char * chblo_dir = g_strdup_printf("%s/chunks/%02x", outputdir, record->chunk_record.chunkhash[0]);
        char * chblo_path = NULL;
        gchar * hexdigest = hexlify_md5(record->chunk_record.chunkhash);
#ifdef LZMA
        chblo_path = g_strdup_printf("%s/%s.chblo.xz", chblo_dir, hexdigest);
#else
        chblo_path = g_strdup_printf("%s/%s.chblo", chblo_dir, hexdigest);
#endif /* LZMA */
        g_free(hexdigest);

        if (g_mkdir_with_parents(chblo_dir, 0755) < 0) {
            g_printerr("Cannot create output directory for chunk '%s': %s\n", chblo_dir, g_strerror(errno));
            exit(38);
        }

        if (g_file_test(chblo_path, G_FILE_TEST_EXISTS)) {
            g_print("chunk block already exists in chunk store: '%s'\n", chblo_path);
        } else {
            int chblofd = g_open(chblo_path, O_CREAT|O_WRONLY, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
            if (chblofd < 0) {
                g_printerr("Cannot create chunk chblo file '%s': %s\n", chblo_path, g_strerror(errno));
                exit(39);
            }

            size_t total_written = 0;
#ifdef LZMA
            total_written = compress(chblofd, chunk_data, record->chunk_record.l);
            g_print("chunk of size %d compressed to %zd\n", record->chunk_record.l, total_written);
#else
            for(int left_to_write=record->chunk_record.l; left_to_write > 0; ) {
                ssize_t written = write(chblofd, chunk_data+pos, MIN(left_to_write, 8192));
                if (written < 0) {
                    g_printerr("error while writing chunk chblo '%s': %s\n", chblo_path, g_strerror(errno));
                    exit(40);
                }
                g_print("%d  ", written);
                total_written += written;
                left_to_write -= written;
            }
#endif /* LZMA */
            g_print("wrote %zd bytes, expected %d\n", total_written, record->chunk_record.l);
            g_close(chblofd, NULL);
        }

        free(chunk_data);
        g_free(chblo_dir);
        g_free(chblo_path);
    }
    g_close(imgfd, NULL);
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
    int fd = g_open(idx_filename, O_CREAT|O_WRONLY, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
    if (fd < 0) {
        g_printerr("Cannot create chunk index file '%s': %s\n", idx_filename, g_strerror(errno));
        exit(35);
    }
    write_chunkindex_header(fd, wholefile_digest);

    /* iter over chunk records */
    for (unsigned int i = 0; i < chunk_records->len; i++)
    {
        chidx_chunk_record_t * record = g_ptr_array_index(chunk_records, i);
        /* write chunk record to index file */
        uint32_t nl = g_htonl(record->chunk_record.l);
        if (write(fd, &nl, 4) <= 0) {
            g_printerr("error while trying to write chunk index file chunk record: %s", g_strerror(errno));
            exit(37);
        }

        if (write(fd, record->chunk_record.chunkhash, MD5_DIGEST_LENGTH) <= 0) { /* chunk checksum */
            g_printerr("error while trying to write chunk index file chunk record: %s", g_strerror(errno));
            exit(37);
        }
    }
    g_close(fd, NULL);
    return(0);
}

static int indexer_main(void)
{
    char * image_path = realpath(indexer_image, NULL);
    if (image_path == NULL) g_printerr("image_path is NULL: %s\n", g_strerror(errno));
    // todo error handling

    gchar * image_dir = g_path_get_dirname(image_path);
    gchar * image_fname = g_path_get_basename(image_path);

    if (g_mkdir_with_parents(indexer_outdir, 0755) < 0) {
        g_printerr("Cannot create output directory for chunks and index file '%s': %s\n", indexer_outdir, g_strerror(errno));
        exit(34);
    }

    char * outputdir = realpath(indexer_outdir, NULL);
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
    uint8_t * wholefile_digest = whole_file_checksum(image_path);

    g_print("indexing...\n");
    GPtrArray * chunk_records = g_ptr_array_new();
    GHashTable * chunk_refcnt_table = g_hash_table_new(g_bytes_hash, g_bytes_equal);
    index_a_file(image_path, chunk_records, chunk_refcnt_table);
    g_print("chunk_records = %p\n", (void *)chunk_records);
    write_chidx(index_path, image_path, wholefile_digest, chunk_records);
    if (! indexer_index_only) {
        write_chblos(image_path, outputdir, chunk_records);
    }

    /* iter over chunk_refcnt_table to count duplicates */
    int total_chunks = 0;
    int unique_chunks = 0;
    GHashTableIter iter;
    long tmpcount;
    g_hash_table_iter_init(&iter, chunk_refcnt_table);
    while (g_hash_table_iter_next(&iter, NULL,  (gpointer)&tmpcount)) {

        total_chunks += tmpcount;
        unique_chunks += 1;
        g_print("total chunks now: %d   unique now %d\n", total_chunks, unique_chunks);

    }
    g_print("chunks total: %d  unique: %d\n", total_chunks, unique_chunks);

    g_ptr_array_free(chunk_records, TRUE); // TODO do other cleanup/free stuff required by GPtrArray
    g_hash_table_destroy(chunk_refcnt_table); // TODO do other cleanup as needed for hash tables


    g_print("MD5 of image file: ");
    for(int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        g_print("%02x", wholefile_digest[i]);
    }
    g_print("\n");

    g_free(indexer_image);
    g_free(indexer_outdir);
    free(image_path);
    free(outputdir);
    free(wholefile_digest);
    g_free(image_dir);
    g_free(image_fname);
    g_free(index_path);

    g_close(fd, NULL);
    return 0;
}

static char * abspath_mkdir(gchar * relpath) {
    /* if file exists, use realpath() */
    if (g_file_test(relpath, G_FILE_TEST_EXISTS)) {
        return realpath(relpath, NULL);
    }
    /* dir exists, but not file, use realpath() on dir, then add file basename,
       otherwise create dir and then repeat the above */
    gchar * dirname = g_path_get_dirname(relpath);
    if (! g_file_test(dirname, G_FILE_TEST_EXISTS)) {
        if (g_mkdir_with_parents(dirname, 0755) < 0) {
            g_printerr("Cannot create directory '%s': %s\n", dirname, g_strerror(errno));
            exit(1);
        }
    }
    gchar * fname = g_path_get_basename(relpath);
    char * dirname_abs = realpath(dirname, NULL);
    char * abspath = g_strdup_printf("%s/%s", dirname_abs, fname);
    free(dirname_abs);
    free(fname);
    g_free(dirname);
    return(abspath);
}

static size_t receive_data_from_curl(void *buffer, size_t size, size_t nmemb, void *userp)
{
    int tempfd = *(int *)userp;
    //decompress_stream(buffer, size*nmemb, tfd);
    if (write(tempfd, buffer, size*nmemb) < 0) {
        g_printerr("handler for remote retrieval encountered a write error to temp file: %s\n", g_strerror(errno));
        exit(99);
    }
    return size*nmemb;
}

static void patcher_stats_to_json(void)
{
    if(! patcher_stats_out) {
        return;
    }
    int fd = g_open(patcher_stats_out, O_CREAT|O_WRONLY, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
    if (fd < 0) {
        g_printerr("Cannot create/write json stats file '%s': %s\n", patcher_stats_out, g_strerror(errno));
        return;
    }
    const unsigned int jsonlen = 1024;
    char s[jsonlen];
    int l = snprintf(s, jsonlen,
                     "{"                                \
                     "    \"chunks_fetched\": %d,"          \
                     "    \"chunks_local\": %d,"            \
                     "    \"bytes_fetched\": %zd,"           \
                     "    \"bytes_fetched_actual\": %zd,"    \
                     "    \"bytes_local\": %zd,"             \
                     "    \"chunks_already_present\": %d,"  \
                     "    \"bytes_already_present )\": %zd"  \
                     "}",
             patch_stats.chunks_fetched,
             patch_stats.chunks_local,
             patch_stats.bytes_fetched,
             patch_stats.bytes_fetched_actual,
             patch_stats.bytes_local,
             patch_stats.chunks_already_present,
             patch_stats.bytes_already_present );
    if (write(fd, s ,l) < 0) {
        g_printerr("Cannot write to json stats file '%s': %s\n", patcher_stats_out, g_strerror(errno));
        close(fd);
        return;
    }
    close(fd);
    return;
}


static int patcher_main(int num_reference_images)
{
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != 0) {
        g_printerr("libcurl init failed\n");
        exit(80);
    }

    ceh = curl_easy_init();
    if (ceh == NULL) {
        g_printerr("libcurl easy init failed\n");
        exit(81);
    }
    curl_easy_setopt(ceh, CURLOPT_WRITEFUNCTION, receive_data_from_curl);

    g_print("patching image '%s' (index: '%s')\n", patcher_out_img, patcher_index_file);

    if (! g_file_test(patcher_index_file, (G_FILE_TEST_EXISTS | G_FILE_TEST_IS_REGULAR))) {
        g_printerr("index file not found: '%s'\n", patcher_index_file);
        exit(60);
    }

    char * target_image_path = abspath_mkdir(patcher_out_img);
    gchar * target_image_dir = g_path_get_dirname(target_image_path);
    gchar * target_image_fname = g_path_get_basename(target_image_path);

    char * target_index_path = realpath(patcher_index_file, NULL);
    gchar * target_index_dir = g_path_get_dirname(target_index_path);
    gchar * target_index_fname = g_path_get_basename(target_index_path);

    /* load target chunk index file */
    GPtrArray *target_chunk_list = g_ptr_array_new();
    chidx_header_t target_index_hdr;
    GPtrArray *reference_chunk_list[num_reference_images];
    chidx_header_t reference_index_hdr[num_reference_images];
    int reference_image_fds[num_reference_images];

    parse_chidx(target_index_path, &target_index_hdr, target_chunk_list);

    /* load reference chunk index files, if any */
    for(int i=0; i<num_reference_images; i++) {
        g_print("loading reference index '%s'\n", patcher_reference_index_array[i]);
        if (! g_file_test(patcher_reference_index_array[i], (G_FILE_TEST_EXISTS | G_FILE_TEST_IS_REGULAR))) {
            g_printerr("reference index file not found: '%s'\n", patcher_reference_index_array[i]);
            exit(62);
        }
        if (! g_file_test(patcher_reference_image_array[i], (G_FILE_TEST_EXISTS | G_FILE_TEST_IS_REGULAR))) {
            g_printerr("reference image file not found: '%s'\n", patcher_reference_image_array[i]);
            exit(63);
        }
        reference_chunk_list[i] = g_ptr_array_new();
        parse_chidx(patcher_reference_index_array[i], &(reference_index_hdr[i]), reference_chunk_list[i]);
        /* check if MD5 from index matches reference image full file checksum */
        g_print("checksumming image '%s' ...\n", patcher_reference_image_array[i]);
        uint8_t * reference_file_digest = whole_file_checksum(patcher_reference_image_array[i]);
        if (memcmp(reference_index_hdr[i].fullfilehash, reference_file_digest, MD5_DIGEST_LENGTH) != 0) {
            g_printerr("checksum mismatch between reference image file and what index file says it should be:\n");
            g_printerr("    checksum stored in index file '%s': %s\n", patcher_reference_index_array[i], hexlify_md5(reference_index_hdr[i].fullfilehash));
            g_printerr("    checksum of image file '%s': %s\n", patcher_reference_image_array[i], hexlify_md5(reference_file_digest));
            exit(64); // this error could probably be ignored, by just not using this reference
        }
        free(reference_file_digest);

        /* open image files for read access */
        reference_image_fds[i] = g_open(patcher_reference_image_array[i], O_RDONLY);
        if (reference_image_fds[i] < 0) {
            g_printerr("Cannot open reference image file '%s': %s\n", patcher_reference_image_array[i], g_strerror(errno));
            exit(65);
        }
    }

    /* does target image already exist? */
    gboolean target_image_exists = FALSE;
    if (g_file_test(target_image_path, (G_FILE_TEST_EXISTS | G_FILE_TEST_IS_REGULAR))) {
        target_image_exists = TRUE;
    }

    GPtrArray *target_asis_chunk_list = g_ptr_array_new();
    /* handle incremental updates of target image, ie. interrupted updates. */
    if (target_image_exists && ! patcher_force_overwrite) {
        /* first, checksum of whole file, maybe we can avoid indexing it if its already complete */
        uint8_t * wholefile_digest = whole_file_checksum(target_image_path);
        if (memcmp(wholefile_digest, target_index_hdr.fullfilehash, MD5_DIGEST_LENGTH) == 0) {
            /* compute stats */
            chidx_chunk_record_t * target_record = g_ptr_array_index(target_chunk_list, target_chunk_list->len - 1);
            patch_stats.bytes_already_present += target_record->offset + target_record->chunk_record.l;
            patch_stats.chunks_already_present = target_chunk_list->len;
            /* image already complete, so we're done */
            goto index_done;
        }
        /* index target image */
        index_a_file(target_image_path, target_asis_chunk_list, NULL);
        /* target_asis_chunk_list  aka   outimg_chunksums = [] */
    }
    int tfd = -1;
    if (target_image_exists) {
        tfd = open(target_image_path, O_RDWR);
    } else {
        tfd = open(target_image_path, O_RDWR | O_CREAT, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
    }
    if (tfd < 0) {
        g_printerr("Cannot create/open target image file '%s': %s\n", target_image_path, g_strerror(errno));
        exit(66);
    }
    if (patcher_force_overwrite) {
        /* truncate and seek to 0 */
        if (ftruncate(tfd, 0) < 0) {
            g_printerr("Cannot truncate target image file '%s': %s\n", target_image_path, g_strerror(errno));
            exit(67);
        }
    }
    if (lseek(tfd, 0, SEEK_SET) < 0) {
        g_printerr("Cannot seek target image file '%s': %s\n", target_image_path, g_strerror(errno));
        exit(68);
    }

    off_t imglen = 0;
    for (unsigned int i = 0; i < target_chunk_list->len; i++)
    {
        chidx_chunk_record_t * target_record = g_ptr_array_index(target_chunk_list, i);
        imglen += target_record->chunk_record.l;
        /* first check if chunk is already in place, if: target_image_exists && ! patcher_force_overwrite   and make sure we're not running over the end of asis list */
        if (target_image_exists && ! patcher_force_overwrite && target_asis_chunk_list->len > i) {
            chidx_chunk_record_t * target_asis_record = g_ptr_array_index(target_asis_chunk_list, i);
            if (memcmp(target_record->chunk_record.chunkhash, target_asis_record->chunk_record.chunkhash, MD5_DIGEST_LENGTH) == 0) {
                g_print("chunk %d already correct in target image\n", i);
                patch_stats.bytes_already_present += target_record->chunk_record.l;
                patch_stats.chunks_already_present += 1;
                continue;
            }
        }

        /* seek in the target image */
        if (lseek(tfd, target_record->offset, SEEK_SET) < 0) {
          g_printerr("Cannot seek target image file '%s': %s\n", target_image_path, g_strerror(errno));
            exit(69);
        }
        gboolean chunk_found_in_ref = FALSE;
        /* next, check if the chunk exists in a local reference image */
        for(int r=0; r<num_reference_images; r++) {
            /* future optimization: use a hash to look up the index instead of iterating over list  */
            for (unsigned int x = 0; x < reference_chunk_list[r]->len; x++) {
                chidx_chunk_record_t * reference_record = g_ptr_array_index(reference_chunk_list[r], x);
                if(memcmp(target_record->chunk_record.chunkhash, reference_record->chunk_record.chunkhash, MD5_DIGEST_LENGTH) == 0) {
                    /* seek in reference image, read from reference, and insert chunk into target image */
                    if (lseek(reference_image_fds[r], reference_record->offset, SEEK_SET) < 0) {
                        g_printerr("Cannot seek reference image file '%s': %s\n", target_image_path, g_strerror(errno));
                        exit(70);
                    }
                    size_t l = target_record->chunk_record.l;
                    uint8_t * chunk_data = malloc(l);
                    if (chunk_data == NULL) {
                        g_printerr("memory allocation error at %s:%d\n", __FILE__, __LINE__);
                        exit(9);
                    }
                    int num_read = read(reference_image_fds[r], chunk_data, l);
                    if (num_read < 0) {
                        g_printerr("read error while trying to extract chunk from reference image '%s': %s\n", patcher_reference_image_array[r], g_strerror(errno));
                        exit(71);
                    }
                    int num_written = write(tfd, chunk_data, l);
                    if (num_written < 0) {
                        g_printerr("write error while inserting chunk into target image '%s': %s\n", target_image_path, g_strerror(errno));
                        exit(72);
                    }
                    free(chunk_data);
                    chunk_found_in_ref = TRUE;
                    /* update stats */
                    patch_stats.chunks_local += 1;
                    patch_stats.bytes_local += l;
                    break;
                }
            }
            if (chunk_found_in_ref) {
                break;
            }
        }
        if (chunk_found_in_ref) {
            continue;
        }

        /* otherwise download the chunk from the remote chunk store */
        gchar * hexdigest = hexlify_md5(target_record->chunk_record.chunkhash);
        int chunk_compressed_size;
        if(url_is_local) {
            int chblo_fd = -1;
            gchar * chblo_path = g_strdup_printf("%s/chunks/%02x/%s.chblo.xz", patcher_url, target_record->chunk_record.chunkhash[0], hexdigest);
            g_print("retrieving chunk #%d with checksum %s from local file '%s'\n", i, hexdigest, chblo_path);
            if ((chblo_fd = open(chblo_path, O_RDONLY)) < 0) {
                g_printerr("could not open chblo '%s': %s\n", chblo_path, g_strerror(errno));
                exit(70);
            }

            decompress(chblo_fd, tfd, &chunk_compressed_size);
            patch_stats.bytes_fetched += target_record->chunk_record.l;
            patch_stats.bytes_fetched_actual += chunk_compressed_size;
            g_free(chblo_path);
            //continue;
        } else { /* remote url */
            gchar tmpfilename[] = "/tmp/.chblo.XXXXXX";
            gchar * chblo_url = g_strdup_printf("%s/chunks/%02x/%s.chblo.xz", patcher_url, target_record->chunk_record.chunkhash[0], hexdigest);
            int tempfd = g_mkstemp(tmpfilename);
            unlink(tmpfilename);
            curl_easy_setopt(ceh, CURLOPT_WRITEDATA, &tempfd);
            //curl_easy_setopt(ceh, CURLOPT_WRITEDATA, &tfd);
            g_print("retrieving chunk #%d with checksum %s from remote URL '%s'\n", i, hexdigest, chblo_url);
            CURLcode res = curl_easy_setopt(ceh, CURLOPT_URL, chblo_url);
            if (res != CURLE_OK) {
                g_printerr("curl set url failed ret=%d\n", res);
                exit(71);
            }

            res = curl_easy_perform(ceh);
            if (res != CURLE_OK) {
                g_printerr("could not fetch remote chunk block ret=%d\n", res);
                exit(72);
            }
            lseek(tempfd, 0, SEEK_SET);
            decompress(tempfd, tfd, &chunk_compressed_size);
            patch_stats.bytes_fetched += target_record->chunk_record.l;
            patch_stats.bytes_fetched_actual += chunk_compressed_size;
            close(tempfd);
            g_free(chblo_url);
        }
        g_free(hexdigest);
    }

    // truncate if img was larger that final size
    if (ftruncate(tfd, imglen) < 0) {
        g_printerr("Warning, cannot truncate target image file '%s': %s\n", target_image_path, g_strerror(errno));
    }

    close(tfd);

    /* write a json file with stats of the patching operation */
    patcher_stats_to_json();

index_done:
    // todo free target_chunk_list
    g_free(target_index_dir);
    g_free(target_index_fname);
    g_free(target_image_dir);
    g_free(target_image_fname);

    free(target_image_path);
    free(target_index_path);

    //TODO g_free  target_chunk_list
    //TODO g_free reference_chunk_list[]
    /* close reference images */
    for(int i=0; i<num_reference_images; i++) {
        g_close(reference_image_fds[i], NULL);
    }

    curl_easy_cleanup(ceh);
    return(0);
}


static int patch_args(int argc, char ** argv)
{
    GOptionContext * context = g_option_context_new ("patch <IMAGE> <INDEX>");
    g_option_context_set_help_enabled(context, TRUE);
    g_option_context_add_main_entries(context, patcher_entries, NULL);
    g_option_context_set_description(context,
                                     "\n" \
                                     "Copyright (C) 2019 by Manuel Bessler\n" \
                                     "License: GPLv2\n"
        );
    GError *error = NULL;
    if (!g_option_context_parse (context, &argc, &argv, &error)) {
        g_printerr ("%s\n", error->message);
        g_error_free(error);
        usage(context);
        return(1);
    }
    g_option_context_free (context);

    if (patcher_url == NULL) {
        g_print("%s: required argument -u/--url missing\n", g_get_prgname());
        exit(1);
    }
    if (patcher_rest == NULL || patcher_rest[0] == NULL)
    {
        g_printerr("%s: missing argument: IMAGE\n", g_get_prgname());
        exit(1);
    }
    if (patcher_rest[1] == NULL || patcher_rest[2] != NULL)
    {
        g_printerr("%s: missing argument: INDEX\n", g_get_prgname());
        exit(1);
    }
    if (patcher_rest[2] != NULL)
    {
        g_printerr("%s: too many arguments\n", g_get_prgname());
        exit(1);
    }

    patcher_out_img = g_strdup (patcher_rest[0]);
    patcher_index_file = g_strdup (patcher_rest[1]);

    /* ensure reference the same number image/index files were given (later we check that the index file and the image match via file checksum) */
    if ( (patcher_reference_image_array != NULL && patcher_reference_index_array == NULL) ||
         (patcher_reference_image_array == NULL && patcher_reference_index_array != NULL)) {
        g_printerr("need matching number of reference image and reference index options (need the same number of '-r' and '-R')\n");
        exit(1);
    }

    /* from here on, patcher_reference_image_array & patcher_reference_index_array are both either NULL or non-NULL */
    if ( patcher_reference_image_array != NULL ) {
        /* check that there are the same number of reference index/image files provided */
        if (g_strv_length(patcher_reference_image_array) != g_strv_length(patcher_reference_index_array)) {
            g_printerr("need matching number of reference image and reference index options (need the same number of '-r' and '-R')\n");
            exit(1);
        }
    }
    int num_reference_images = 0;
    if ( patcher_reference_image_array != NULL && g_strv_length(patcher_reference_image_array) > 0 ) {
        num_reference_images = g_strv_length(patcher_reference_image_array);
    } else {
        g_print("ok, no reference images!\n");
    }


    char * uri_scheme = g_uri_parse_scheme(patcher_url);
    url_is_local = FALSE;

    if ( uri_scheme != NULL) {
        if (g_strcmp0(uri_scheme, "http") == 0) {
        } else if (g_strcmp0(uri_scheme, "https") == 0) {
        } else if (g_strcmp0(uri_scheme, "ftp") == 0) {
        } else if (g_strcmp0(uri_scheme, "file") == 0) {
            url_is_local = TRUE;
            //patcher_url += strlen("file://") ;
        } else {
        }
    } else {
        url_is_local = TRUE;
    }
    g_print("URL: is %slocal\n", (url_is_local)?"":"not");
    free(uri_scheme);

    return(patcher_main(num_reference_images));
}

static int index_args(int argc, char ** argv) {
    GOptionContext * context = g_option_context_new ("index <IMAGE> <OUTDIR>");
    g_option_context_set_help_enabled(context, TRUE);
    g_option_context_add_main_entries(context, indexer_entries, NULL);
    g_option_context_set_description(context,
                                     "\n" \
                                     "Copyright (C) 2019 by Manuel Bessler\n" \
                                     "License: GPLv2\n"
        );
    GError *error = NULL;
    if (!g_option_context_parse (context, &argc, &argv, &error)) {
        g_printerr ("%s\n", error->message);
        g_error_free(error);
        usage(context);
        return(1);
    }

    g_option_context_free (context);

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
    return(indexer_main());
}

static void main_usage(const char * argv0)
{
    g_printerr("imidj - IMage Incremental Deltafragment Joiner\n" \
               "Copyright (C) 2019 by Manuel Bessler\n"         \
               "License: GPLv2\n"                               \
               "\n");
    g_printerr("Usage:\n");
    g_printerr("  %s <COMMAND> ...\n", argv0);
    g_printerr("\n");
    g_printerr ("List of imidj commands:\n");
    g_printerr ("    index\t\tIndex and Chunk an Image File\n");
    g_printerr ("    patch\t\tCreate/Update an Image File from chunks,\n");
    g_printerr ("         \t\t optionally referencing one or more similar local images\n");
    exit(1);
}

int main(int argc, char ** argv) {
    mode_dispatch_handler_t action;

    if (argc < 2) {
        main_usage(argv[0]);
        exit(1);
    }

    if (g_str_equal (argv[1], "index")) {
        action = index_args;
    } else if (g_str_equal (argv[1], "patch")) {
        action = patch_args;
    //} else if (g_str_equal (argv[1], "analyze")) {
        //action = secret_tool_action_analyze;
    } else if (g_str_equal(argv[1], "version") || g_str_equal(argv[1], "--version")) {
        action = version_main;
    } else {
        main_usage(argv[0]);
        exit(1);
    }

    argv[1] = argv[0];
    exit( (action) (argc - 1, argv + 1) );
}
