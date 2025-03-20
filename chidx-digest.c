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

/* libcrypto includes */
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/objects.h>

#include "chidx-digest.h"

uint16_t hashsize_from_hashtype(hash_type_t htype) {
    switch (htype) {
    case IMIDJ_HASH_MD5:
        return MD5_DIGEST_LENGTH;
    case IMIDJ_HASH_SHA256:
        return SHA256_DIGEST_LENGTH;
    default:
        return 0;
    }
}

const gchar * hashname_from_hashtype(hash_type_t htype) {
    switch (htype) {
    case IMIDJ_HASH_SHA256:
        return "SHA256";
    case IMIDJ_HASH_MD5:
        return "MD5";
    default:
        return "";
    }
}

gchar * hexlify_digest(hash_type_t htype, uint8_t digest[]) {
    uint16_t hs = hashsize_from_hashtype(htype);
    gchar * hexdigest = g_malloc0(hs*2+1);
    if (hexdigest == NULL) {
        g_printerr("memory allocation failed (at %s:%d): %s\n", __FILE__, __LINE__, g_strerror(errno));
        exit(105);
    }

    for(int i = 0; i < hs; i++) {
        gchar hexdigit[3];
        g_snprintf(hexdigit, 3, "%02x", digest[i]);
        (void)g_strlcat(hexdigest, hexdigit, hs*2+1);
    }
    return(hexdigest);
}


uint8_t * calculate_digest(hash_type_t htype, uint8_t * data, ssize_t len) {
    uint8_t * digest = g_malloc0(hashsize_from_hashtype(htype));
    if (digest == NULL) {
        g_printerr("memory allocation failed (at %s:%d): %s\n", __FILE__, __LINE__, g_strerror(errno));
        exit(105);
    }
    int nid = -1;
    switch(htype) {
    case IMIDJ_HASH_MD5: nid = NID_md5; break;
    case IMIDJ_HASH_SHA256: nid = NID_sha256; break;
    default: nid = -1;
    }

    unsigned int digestlen;
    const EVP_MD * digesttype = EVP_get_digestbynid(nid);
    if (digesttype == NULL) {
        printf("Unknown message digest: %d\n", htype);
        exit(106);
    }
    EVP_MD_CTX * mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        g_printerr("memory allocation failed for digest context: %s\n", g_strerror(errno));
        exit(101);
    }
    EVP_DigestInit_ex(mdctx, digesttype, NULL);
    EVP_DigestUpdate(mdctx, data, len);
    EVP_DigestFinal_ex(mdctx, digest, &digestlen);
    EVP_MD_CTX_free(mdctx);

    return digest;
}

uint8_t * calculate_digest_file(hash_type_t htype, char * filename) {
    /* checksum whole file */
    int fd = g_open(filename, O_RDONLY);
    if (fd < 0) {
        g_printerr("cannot open file for checksumming '%s': %s\n", filename, g_strerror(errno));
        exit(102);
    }

    uint16_t digest_length = hashsize_from_hashtype(htype);
    ////////////////////
    uint8_t * digest = g_malloc0(digest_length);
    if (digest == NULL) {
        g_printerr("memory allocation failed for file checksumming: %s\n", g_strerror(errno));
        exit(101);
    }
    int nid = -1;
    switch(htype) {
    case IMIDJ_HASH_MD5: nid = NID_md5; break;
    case IMIDJ_HASH_SHA256: nid = NID_sha256; break;
    default: nid = -1;
    }

    unsigned int digestlen;
    const EVP_MD *digesttype = EVP_get_digestbynid(nid);
    if (digesttype == NULL) {
        printf("Unknown message digest: %d\n", htype);
        exit(106);
    }
    EVP_MD_CTX * mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        g_printerr("memory allocation failed for digest context: %s\n", g_strerror(errno));
        exit(101);
    }
    EVP_DigestInit_ex(mdctx, digesttype, NULL);

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
        EVP_DigestUpdate(mdctx, buf, num_read);
    }

    EVP_DigestFinal_ex(mdctx, digest, &digestlen);
    EVP_MD_CTX_free(mdctx);
    g_close(fd, NULL);
    return digest;
}
