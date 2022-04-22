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
#include <inttypes.h>

/* glib includes */
#include <glib.h>
#include <glib/gstdio.h>
#include <glib/gprintf.h>

#include "imidj.h"
#include "patcher.h"
#include "chidx.h"
#include "chunker.h"
#include "compressor.h"
#include "chblo.h"

/* libcurl includes */
#include <curl/curl.h>


#define STRINGIFY_(X) #X
#define STRINGIFY(X) STRINGIFY_(X)

static gchar* patcher_index_file = NULL;
static gchar* patcher_out_img = NULL;
static gchar* patcher_url = NULL;
#define PATCHER_DL_RETRY_COUNT_DEFAULT (3)
static gint patcher_dl_retry_count_chunk = PATCHER_DL_RETRY_COUNT_DEFAULT;
#define PATCHER_DL_RETRY_TIMEOUT_SLEEP_MS_DEFAULT (100)
static gint patcher_dl_timeout_sleep_ms = PATCHER_DL_RETRY_TIMEOUT_SLEEP_MS_DEFAULT;
#define PATCHER_DL_CONNECTTIMEOUT_MS_DEFAULT (10000)
static glong patcher_dl_connecttimeout_ms = PATCHER_DL_CONNECTTIMEOUT_MS_DEFAULT;
#define PATCHER_DL_REQUESTTIMEOUT_MS_DEFAULT (60000)
static glong patcher_dl_requesttimeout_ms = PATCHER_DL_REQUESTTIMEOUT_MS_DEFAULT;
static gboolean patcher_force_overwrite = FALSE;
static gboolean patcher_skip_mismatched_refs = FALSE;
static gboolean patcher_skip_verify = FALSE;
static gchar** patcher_reference_index_array = NULL;
static gchar** patcher_reference_image_array = NULL;
static gchar* patcher_stats_out = NULL;
static gchar** patcher_rest = NULL;
static gboolean url_is_local = FALSE;

CURL * ceh = NULL;

imidj_patch_stats_t patch_stats = {
    .chunks_fetched = 0,
    .chunks_local = 0,
    .bytes_fetched = 0,
    .bytes_fetched_actual = 0,
    .bytes_local = 0,
    .chunks_already_present = 0,
    .bytes_already_present = 0 };

GOptionEntry patcher_entries[] = {
    /* imidj patch --force-overwrite --stats-out STATSFILE --url URL -r img1.chidx -R img1.img -r img2.chidx -R img2.img IMAGE INDEX */

    /* required args */
    {"url", 'u', 0, G_OPTION_ARG_STRING, &patcher_url, "Base URL of chunk server. Accepts http/https/ftp or local paths. Do not include the trailing 'chunks/' component", "URL"},

    /* optional args */
    {"force-overwrite", '\0', 0, G_OPTION_ARG_NONE, &patcher_force_overwrite, "Force overwrite output image file if it already exists (no incremental upgrade)", NULL},
    {"stats-out", '\0', 0, G_OPTION_ARG_FILENAME, &patcher_stats_out, "Output JSON statistics to STATSFILE", "STATSFILE"},
    {"reference-index", 'r', 0, G_OPTION_ARG_FILENAME_ARRAY, &patcher_reference_index_array, "Index file for reference image (Ignored, no longer required)", "INDEXFILE"},
    {"reference-image", 'R', 0, G_OPTION_ARG_FILENAME_ARRAY, &patcher_reference_image_array, "Existing image file as reference (requires matching '-r'; can be specified zero or more times) ", "IMAGEFILE"},
    {"skip-mismatched-references", '\0', 0, G_OPTION_ARG_NONE, &patcher_skip_mismatched_refs, "Skip if a reference image mismatches its chunk index (instead of exit w/ error)", NULL},
    {"skip-verify", '\0',  0, G_OPTION_ARG_NONE, &patcher_skip_verify, "Skip image checksum verification checksum after (re)building from chunks. (Saves a bit of time but won't catch corrupted files.)", NULL},
    {"dl-num-retries", '\0',  0, G_OPTION_ARG_INT, &patcher_dl_retry_count_chunk, "Number of retries for failed chunk downloads (default: " STRINGIFY(PATCHER_DL_RETRY_COUNT_DEFAULT) ")", "N"},
    {"dl-sleep-before-retry", '\0',  0, G_OPTION_ARG_INT, &patcher_dl_timeout_sleep_ms, "Number of milliseconds to sleep before retrying chunk download after a timeout (default: " STRINGIFY(PATCHER_DL_RETRY_TIMEOUT_SLEEP_MS_DEFAULT) ")", "MS"},
    {"dl-connecttimeout", '\0', 0, G_OPTION_ARG_INT, &patcher_dl_connecttimeout_ms, "Number of milliseconds after which a connect attempt is allwed to take before retrying (default: " STRINGIFY(PATCHER_DL_CONNECTTIMEOUT_MS_DEFAULT) ")", "MS"},
    {"dl-requesttimeout", '\0', 0, G_OPTION_ARG_INT, &patcher_dl_requesttimeout_ms, "Number of milliseconds a chunk download is allowed to take before retrying, applies per chunk (default: " STRINGIFY(PATCHER_DL_REQUESTTIMEOUT_MS_DEFAULT) ")", "MS"},
    {"verbose", 'v', 0, G_OPTION_ARG_NONE, &opt_verbose, "Increase output verbosity", NULL },
    /* general */
    {"version", 'V', 0, G_OPTION_ARG_NONE, &opt_version, "Show version information", NULL },
    /* remaining args */
    {G_OPTION_REMAINING, 0, 0, G_OPTION_ARG_FILENAME_ARRAY, &patcher_rest, NULL, NULL},
    {0}
};

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
    if (dirname_abs == NULL) {
        g_printerr("dirname_abs is NULL: %s\n", g_strerror(errno));
        exit(33);
    }

    char * abspath = g_strdup_printf("%s/%s", dirname_abs, fname);
    free(dirname_abs);
    free(fname);
    g_free(dirname);
    return(abspath);
}

static size_t receive_data_from_curl(void *buffer, size_t size, size_t nmemb, void *userp)
{
    int tempfd = *(int *)userp;
    /* decompress_stream(buffer, size*nmemb, tfd); */
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
    int fd = g_open(patcher_stats_out, O_CREAT|O_WRONLY|O_TRUNC, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
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
                     "    \"bytes_already_present\": %zd"  \
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
    char cerrbuf[CURL_ERROR_SIZE];
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
    curl_easy_setopt(ceh, CURLOPT_ERRORBUFFER, cerrbuf);

    g_print("patching image '%s' (index: '%s')\n", patcher_out_img, patcher_index_file);

    if (! g_file_test(patcher_index_file, (G_FILE_TEST_EXISTS | G_FILE_TEST_IS_REGULAR))) {
        g_printerr("index file not found: '%s'\n", patcher_index_file);
        exit(60);
    }

    char * target_image_path = abspath_mkdir(patcher_out_img);
    if (target_image_path == NULL) {
        g_printerr("target_image_path is NULL: %s\n", g_strerror(errno));
        exit(33);
    }

    gchar * target_image_dir = g_path_get_dirname(target_image_path);
    gchar * target_image_fname = g_path_get_basename(target_image_path);

    char * target_index_path = realpath(patcher_index_file, NULL);
    if (target_index_path == NULL) {
        g_printerr("target_index_path is NULL: %s\n", g_strerror(errno));
        exit(33);
    }

    gchar * target_index_dir = g_path_get_dirname(target_index_path);
    gchar * target_index_fname = g_path_get_basename(target_index_path);

    /* load target chunk index file */
    GPtrArray *target_chunk_list = g_ptr_array_new_with_free_func((GDestroyNotify)chunk_record_free_func);

    chidx_hdr_t target_index_hdr;
    chidx_hdr2_t * target_index_hdr2;
    GPtrArray *reference_chunk_list[num_reference_images];
    int reference_image_fds[num_reference_images];

    parse_chidx(target_index_path, &target_index_hdr, &target_index_hdr2, target_chunk_list);
    if (target_index_hdr2 == NULL) {
        g_printerr("target_index_hdr2 is NULL: %s\n", g_strerror(errno));
        exit(34);
    }

    /* open and index reference image files, if any */
    for(int i=0; i<num_reference_images; i++) {
        if (! g_file_test(patcher_reference_image_array[i], (G_FILE_TEST_EXISTS | G_FILE_TEST_IS_REGULAR))) {
            g_printerr("warning: reference image file not found: '%s'  (ignoring)\n", patcher_reference_image_array[i]);
            /* mark as unavailable */
            reference_image_fds[i] = -1;
            reference_chunk_list[i] = NULL;
            continue;
        }
        reference_chunk_list[i] = g_ptr_array_new_with_free_func((GDestroyNotify)chunk_record_free_func);

        g_printerr("indexing reference image %s...\n", patcher_reference_image_array[i]);
        index_a_file(patcher_reference_image_array[i], DEFAULT_CHUNK_HASH, reference_chunk_list[i], NULL);

        /* open image files for read access */
        reference_image_fds[i] = g_open(patcher_reference_image_array[i], O_RDONLY);
        if (reference_image_fds[i] < 0) {
            g_printerr("Cannot open reference image file '%s': %s\n", patcher_reference_image_array[i], g_strerror(errno));
            /* exit(65); */
            reference_image_fds[i] = -1;
            continue;
        }
    }

    /* does target image already exist? */
    gboolean target_image_exists = FALSE;
    if (g_file_test(target_image_path, (G_FILE_TEST_EXISTS | G_FILE_TEST_IS_REGULAR))) {
        target_image_exists = TRUE;
    }

    GPtrArray *target_asis_chunk_list = g_ptr_array_new_with_free_func((GDestroyNotify)chunk_record_free_func);
    /* handle incremental updates of target image, ie. interrupted updates. */
    if (target_image_exists && ! patcher_force_overwrite) {
        /* index target image */
        index_a_file(target_image_path, DEFAULT_CHUNK_HASH, target_asis_chunk_list, NULL);
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
        g_print("Force-Overwrite active.\n");
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

    ssize_t chunk_digest_length = hashsize_from_hashtype(DEFAULT_CHUNK_HASH);
    off_t imglen = 0;
    for (unsigned int i = 0; i < target_chunk_list->len; i++)
    {
        chidx_chunk_record_t * target_record = g_ptr_array_index(target_chunk_list, i);
        imglen += target_record->l;
        /* first check if chunk is already in place, if: target_image_exists && ! patcher_force_overwrite and make sure we're not running over the end of asis list */
        if (target_image_exists && ! patcher_force_overwrite && target_asis_chunk_list->len > i) {
            chidx_chunk_record_t * target_asis_record = g_ptr_array_index(target_asis_chunk_list, i);
            /* not only compare the chunks here, but also the offset since things might have shifted.
             * In that case, just depend on other sources for this block instead of trying to copy since
             * it was most likely already overwritten by a previous chunk.
             */

            if (target_record->offset == target_asis_record->offset &&
                memcmp(target_record->chunkhash, target_asis_record->chunkhash, chunk_digest_length) == 0) {
                gchar * hexdigest = hexlify_digest(DEFAULT_CHUNK_HASH, target_record->chunkhash);
                if(opt_verbose) { g_print("chunk #%d with checksum %s already correct in target image\n", i, hexdigest); }
                g_free(hexdigest);

                patch_stats.bytes_already_present += target_record->l;
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
            /* skip reference image if its fd is -1 */
            if (reference_image_fds[r] < 0) {
                continue;
            }
            /* skip empty and discarded reference images */
            if (reference_chunk_list[r] == NULL) {
                continue;
            }
            /* future optimization: use a hash to look up the index instead of iterating over list  */
            for (unsigned int x = 0; x < reference_chunk_list[r]->len; x++) {
                chidx_chunk_record_t * reference_record = g_ptr_array_index(reference_chunk_list[r], x);
                if(memcmp(target_record->chunkhash, reference_record->chunkhash, chunk_digest_length) == 0) {
                    /* seek in reference image, read from reference, and insert chunk into target image */
                    if (lseek(reference_image_fds[r], reference_record->offset, SEEK_SET) < 0) {
                        g_printerr("Cannot seek reference image file '%s': %s\n", target_image_path, g_strerror(errno));
                        continue;
                    }
                    size_t l = target_record->l;
                    uint8_t * chunk_data = g_malloc(l);
                    if (chunk_data == NULL) {
                        g_printerr("memory allocation error at %s:%d\n", __FILE__, __LINE__);
                        exit(9);
                    }
                    ssize_t num_read = read(reference_image_fds[r], chunk_data, l);
                    if (num_read < 0) {
                        g_printerr("read error while trying to extract chunk from reference image '%s': %s\n", patcher_reference_image_array[r], g_strerror(errno));
                        continue;
                    }
                    ssize_t num_written = write(tfd, chunk_data, l);
                    if (num_written < 0) {
                        g_printerr("write error while inserting chunk into target image '%s': %s\n", target_image_path, g_strerror(errno));
                        exit(72);
                    } else if ((size_t)num_written != l) {
                        g_printerr("write error while inserting chunk into target image '%s': %s\n", target_image_path, g_strerror(errno));
                        exit(72);
                    }
                    g_free(chunk_data);
                    chunk_found_in_ref = TRUE;
                    gchar * hexdigest = hexlify_digest(DEFAULT_CHUNK_HASH, target_record->chunkhash);
                    if(opt_verbose) { g_print("retrieving chunk #%d with checksum %s from reference image '%s'\n", i, hexdigest, patcher_reference_image_array[r]); }
                    g_free(hexdigest);

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
        gchar * hexdigest = hexlify_digest(DEFAULT_CHUNK_HASH, target_record->chunkhash);
        int chunk_compressed_size = 0;
        if(url_is_local) {
            int chblo_fd = -1;
            gchar * chblo_path = g_strdup_printf("%s/chunks/%02x/%s.chblo" CHUNK_EXT, patcher_url, target_record->chunkhash[0], hexdigest);
            if(opt_verbose) { g_print("retrieving chunk #%d with checksum %s from local file '%s'\n", i, hexdigest, chblo_path); }
            if ((chblo_fd = open(chblo_path, O_RDONLY)) < 0) {
                g_printerr("could not open chblo '%s': %s\n", chblo_path, g_strerror(errno));
                exit(70);
            }

            lzip_decompress(chblo_fd, tfd, &chunk_compressed_size);
            patch_stats.bytes_fetched += target_record->l;
            patch_stats.bytes_fetched_actual += chunk_compressed_size;
            patch_stats.chunks_fetched += 1;
            close(chblo_fd);
            g_free(chblo_path);
            /*continue;*/
        } else { /* remote url */
            gchar tmpfilename[] = "/tmp/.chblo.XXXXXX";
            gchar * chblo_url = g_strdup_printf("%s/chunks/%02x/%s.chblo" CHUNK_EXT, patcher_url, target_record->chunkhash[0], hexdigest);
            int tempfd = g_mkstemp(tmpfilename);
            unlink(tmpfilename);
            curl_easy_setopt(ceh, CURLOPT_WRITEDATA, &tempfd);
            curl_easy_setopt(ceh, CURLOPT_FAILONERROR, 1L);
            curl_easy_setopt(ceh, CURLOPT_TIMEOUT_MS, patcher_dl_requesttimeout_ms);
            curl_easy_setopt(ceh, CURLOPT_CONNECTTIMEOUT_MS, patcher_dl_connecttimeout_ms);

            if(opt_verbose) { g_print("retrieving chunk #%d with checksum %s from remote URL '%s'\n", i, hexdigest, chblo_url); }
            CURLcode res = curl_easy_setopt(ceh, CURLOPT_URL, chblo_url);
            if (res != CURLE_OK) {
                g_printerr("curl set url failed ret=%d\n", res);
                exit(71);
            }

            gint retries;
            patcher_dl_retry_count_chunk += 1; /* add initial attempt to retries */
            for(retries=0; retries < patcher_dl_retry_count_chunk; retries++) {
                cerrbuf[0] = 0;
                res = curl_easy_perform(ceh);
                //g_print("curl_easy_perform returned %d\n", res);
                if (res == CURLE_OK) {
                    break;
                }
                /* retry immediately on some curl errors, sleep for a while and retry on timeout errors, and fail immediatly on all others */
                if (res == CURLE_FTP_ACCEPT_TIMEOUT || res == CURLE_OPERATION_TIMEDOUT) {
                    g_printerr("curl operation timeout, sleeping for %d ms before retry #%d\n", patcher_dl_timeout_sleep_ms, retries+1);
                    g_usleep(1000 * patcher_dl_timeout_sleep_ms);
                    continue;
                }
                if (res == CURLE_HTTP_RETURNED_ERROR ) {
                    g_printerr("curl http error, sleeping for %d ms before retry #%d\n", patcher_dl_timeout_sleep_ms, retries+1);
                    g_usleep(1000 * patcher_dl_timeout_sleep_ms);
                    continue;
                } else if (res == CURLE_COULDNT_RESOLVE_PROXY
                    || res == CURLE_COULDNT_RESOLVE_HOST
                    || res == CURLE_COULDNT_CONNECT
                    || res == CURLE_FTP_ACCEPT_FAILED
                    || res == CURLE_FTP_CANT_GET_HOST
                    || res == CURLE_PARTIAL_FILE
                    || res == CURLE_FTP_COULDNT_RETR_FILE
                    || res == CURLE_SSL_CONNECT_ERROR
                    || res == CURLE_GOT_NOTHING
                    || res == CURLE_SEND_ERROR
                    || res == CURLE_RECV_ERROR
                    || res == CURLE_SSH
                    ) {
                    g_printerr("curl operation timeout, sleeping for %d ms before retry #%d\n", patcher_dl_timeout_sleep_ms, retries+1);
                    g_usleep(1000 * patcher_dl_timeout_sleep_ms);
                    continue;
                }
                break; /* all other errors */
            }
            if (res != CURLE_OK) {
                size_t len = strlen(cerrbuf);
                if(len) {
                    g_printerr("Could not fetch remote chunk block after %d tries ret=%d. %s\n", retries, res, cerrbuf);
                } else {
                    g_printerr("Could not fetch remote chunk block after %d tries ret=%d. %s\n", retries, res, curl_easy_strerror(res));
                }
                exit(72);
            }

            if (lseek(tempfd, 0, SEEK_SET) < 0) {
                g_printerr("Cannot seek downloaded chunk file '%s': %s\n", tmpfilename, g_strerror(errno));
                exit(74);
            }
            //g_print("decompressing chunk %d in %s ...", i, tmpfilename);
            lzip_decompress(tempfd, tfd, &chunk_compressed_size);


            // TODO: turn back on
            /* read-back and checksum the decompressed chunk*/
            {
                uint8_t buf[target_record->l];
                lseek(tfd, target_record->offset, SEEK_SET);
                if( (uint32_t)read(tfd, &buf, target_record->l) != target_record->l ) {
                    g_printerr("error during read-back of written, decompressed new chunk: %s\n", g_strerror(errno));
                    exit(200);
                }

                uint8_t * digest2 = calculate_digest(DEFAULT_CHUNK_HASH, buf, target_record->l);
                gchar * hexdigest2 = hexlify_digest(DEFAULT_CHUNK_HASH, digest2);
                if(opt_verbose) { g_print("Chunk #%d written, checksum after write: %s\n", i, hexdigest2); }
                g_free(hexdigest2);
                g_free(digest2);
            }

            patch_stats.bytes_fetched += target_record->l;
            patch_stats.bytes_fetched_actual += chunk_compressed_size;
            patch_stats.chunks_fetched += 1;
            close(tempfd);
            g_free(chblo_url);
        }
        g_free(hexdigest);
    }

    /* truncate if img was larger that final size */
    if (ftruncate(tfd, imglen) < 0) {
        g_printerr("Warning, cannot truncate target image file '%s': %s\n", target_image_path, g_strerror(errno));
    }

    fsync(tfd);
    close(tfd);

    if (! patcher_skip_verify) {
        ssize_t wholefile_digest_len = hashsize_from_hashtype(target_index_hdr.fullfilehash_type);
        uint8_t * wholefile_digest = calculate_digest_file(target_index_hdr.fullfilehash_type, target_image_path);
        gchar * hexdigest = hexlify_digest(target_index_hdr.fullfilehash_type, wholefile_digest);
        if (memcmp(wholefile_digest, target_index_hdr2->fullfilehash, wholefile_digest_len) != 0) {
            gchar * hexdigest_index_hdr = hexlify_digest(target_index_hdr.fullfilehash_type, target_index_hdr2->fullfilehash);
            g_printerr("verify failed, checksum mismatch: expected %s, found %s\n", hexdigest_index_hdr, hexdigest);
            g_free(hexdigest_index_hdr);
            exit(73);
        } else {
            g_print("verify ok, image checksum is %s\n", hexdigest);
        }
        g_free(hexdigest);
        g_free(wholefile_digest);
    }

    /* write a json file with stats of the patching operation */
    patcher_stats_to_json();

//patcher_index_done:
    g_ptr_array_free(target_asis_chunk_list, TRUE);
    g_ptr_array_free(target_chunk_list, TRUE);
    g_free(target_index_fname);
    g_free(target_index_dir);
    g_free(target_index_hdr2);
    free(target_index_path);

    g_free(target_image_fname);
    g_free(target_image_dir);
    g_free(target_image_path);

    for(int i=0; i<num_reference_images; i++) {
        if (reference_chunk_list[i] != NULL) {
            g_ptr_array_free(reference_chunk_list[i], TRUE);
        }
    }

    /* close reference images */
    for(int i=0; i<num_reference_images; i++) {
        if (reference_image_fds[i] < 0) {
            g_close(reference_image_fds[i], NULL);
        }
    }

    curl_easy_cleanup(ceh);
    return(0);
}


int patcher_args(int argc, char ** argv)
{
    GOptionContext * context = g_option_context_new ("patch <IMAGE> <INDEX>");
    g_option_context_set_help_enabled(context, TRUE);
    g_option_context_add_main_entries(context, patcher_entries, NULL);
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
            /*patcher_url += strlen("file://") ;*/
        } else {
        }
    } else {
        url_is_local = TRUE;
    }
    g_print("URL: is %slocal\n", (url_is_local)?"":"not");
    g_free(uri_scheme);

    int ret = patcher_main(num_reference_images);
    g_free(patcher_index_file);
    g_free(patcher_out_img);
    return ret;
}
