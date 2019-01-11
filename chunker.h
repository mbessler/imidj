#ifndef __IMIDJ_CHUNKER_H
#define __IMIDJ_CHUNKER_H

#include <stdint.h>

typedef struct {
    int window_size, chunk_mask, min_size;
    size_t buf_size;
    uint32_t *table;
    uint8_t *data;
    int fd;
    int done, eof;
    size_t remaining, bytes_read, bytes_yielded, position, last;
} Chunker;

typedef enum {
    CHUNKER_ERROR_NONE = 0,
    CHUNKER_ERROR_MEM_ALLOC,
    CHUNKER_ERROR_BYTE_COUNT_MISMATCH,
    CHUNKER_ERROR_READ,
    //CHUNKER_ERROR_,
} chunker_error_t;

typedef struct {
    size_t len;
    chunker_error_t error;
    uint8_t * data;
} raw_chunk_w_size_t;

Chunker * chunker_init(int window_size, int chunk_mask, int min_size, uint32_t seed);
void chunker_set_fd(Chunker *c, int fd);
void chunker_free(Chunker *c);
raw_chunk_w_size_t chunker_process(Chunker *c);

#endif /* __IMIDJ_CHUNKER_H */
