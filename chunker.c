#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "chunker.h"

/* Cyclic polynomial / buzhash: https://en.wikipedia.org/wiki/Rolling_hash */

static uint32_t table_base[] =
{
    0xe7f831ec, 0xf4026465, 0xafb50cae, 0x6d553c7a, 0xd639efe3, 0x19a7b895, 0x9aba5b21, 0x5417d6d4,
    0x35fd2b84, 0xd1f6a159, 0x3f8e323f, 0xb419551c, 0xf444cebf, 0x21dc3b80, 0xde8d1e36, 0x84a32436,
    0xbeb35a9d, 0xa36f24aa, 0xa4e60186, 0x98d18ffe, 0x3f042f9e, 0xdb228bcd, 0x096474b7, 0x5c20c2f7,
    0xf9eec872, 0xe8625275, 0xb9d38f80, 0xd48eb716, 0x22a950b4, 0x3cbaaeaa, 0xc37cddd3, 0x8fea6f6a,
    0x1d55d526, 0x7fd6d3b3, 0xdaa072ee, 0x4345ac40, 0xa077c642, 0x8f2bd45b, 0x28509110, 0x55557613,
    0xffc17311, 0xd961ffef, 0xe532c287, 0xaab95937, 0x46d38365, 0xb065c703, 0xf2d91d0f, 0x92cd4bb0,
    0x4007c712, 0xf35509dd, 0x505b2f69, 0x557ead81, 0x310f4563, 0xbddc5be8, 0x9760f38c, 0x701e0205,
    0x00157244, 0x14912826, 0xdc4ca32b, 0x67b196de, 0x5db292e8, 0x8c1b406b, 0x01f34075, 0xfa2520f7,
    0x73bc37ab, 0x1e18bc30, 0xfe2c6cb3, 0x20c522d0, 0x5639e3db, 0x942bda35, 0x899af9d1, 0xced44035,
    0x98cc025b, 0x255f5771, 0x70fefa24, 0xe928fa4d, 0x2c030405, 0xb9325590, 0x20cb63bd, 0xa166305d,
    0x80e52c0a, 0xa8fafe2f, 0x1ad13f7d, 0xcfaf3685, 0x6c83a199, 0x7d26718a, 0xde5dfcd9, 0x79cf7355,
    0x8979d7fb, 0xebf8c55e, 0xebe408e4, 0xcd2affba, 0xe483be6e, 0xe239d6de, 0x5dc1e9e0, 0x0473931f,
    0x851b097c, 0xac5db249, 0x09c0f9f2, 0xd8d2f134, 0xe6f38e41, 0xb1c71bf1, 0x52b6e4db, 0x07224424,
    0x6cf73e85, 0x4f25d89c, 0x782a7d74, 0x10a68dcd, 0x3a868189, 0xd570d2dc, 0x69630745, 0x9542ed86,
    0x331cd6b2, 0xa84b5b28, 0x07879c9d, 0x38372f64, 0x7185db11, 0x25ba7c83, 0x01061523, 0xe6792f9f,
    0xe5df07d1, 0x4321b47f, 0x7d2469d8, 0x1a3a4f90, 0x48be29a3, 0x669071af, 0x8ec8dd31, 0x0810bfbf,
    0x813a06b4, 0x68538345, 0x65865ddc, 0x43a71b8e, 0x78619a56, 0x5a34451d, 0x5bdaa3ed, 0x71edc7e9,
    0x17ac9a20, 0x78d10bfa, 0x6c1e7f35, 0xd51839d9, 0x240cbc51, 0x33513cc1, 0xd2b4f795, 0xccaa8186,
    0x0babe682, 0xa33cf164, 0x18c643ea, 0xc1ca105f, 0x9959147a, 0x6d3d94de, 0x0b654fbe, 0xed902ca0,
    0x7d835cb5, 0x99ba1509, 0x6445c922, 0x495e76c2, 0xf07194bc, 0xa1631d7e, 0x677076a5, 0x89fffe35,
    0x1a49bcf3, 0x8e6c948a, 0x0144c917, 0x8d93aea1, 0x16f87ddf, 0xc8f25d49, 0x1fb11297, 0x27e750cd,
    0x2f422da1, 0xdee89a77, 0x1534c643, 0x457b7b8b, 0xaf172f7a, 0x6b9b09d6, 0x33573f7f, 0xf14e15c4,
    0x526467d5, 0xaf488241, 0x87c3ee0d, 0x33be490c, 0x95aa6e52, 0x43ec242e, 0xd77de99b, 0xd018334f,
    0x5b78d407, 0x498eb66b, 0xb1279fa8, 0xb38b0ea6, 0x90718376, 0xe325dee2, 0x8e2f2cba, 0xcaa5bdec,
    0x9d652c56, 0xad68f5cb, 0xa77591af, 0x88e37ee8, 0xf8faa221, 0xfcbbbe47, 0x4f407786, 0xaf393889,
    0xf444a1d9, 0x15ae1a2f, 0x40aa7097, 0x6f9486ac, 0x29d232a3, 0xe47609e9, 0xe8b631ff, 0xba8565f4,
    0x11288749, 0x46c9a838, 0xeb1b7cd8, 0xf516bbb1, 0xfb74fda0, 0x010996e6, 0x4c994653, 0x1d889512,
    0x53dcd9a3, 0xdd074697, 0x1e78e17c, 0x637c98bf, 0x930bb219, 0xcf7f75b0, 0xcb9355fb, 0x9e623009,
    0xe466d82c, 0x28f968d3, 0xfeb385d9, 0x238e026c, 0xb8ed0560, 0x0c6a027a, 0x3d6fec4b, 0xbb4b2ec2,
    0xe715031c, 0xeded011d, 0xcdc4d3b9, 0xc456fc96, 0xdd0eea20, 0xb3df8ec9, 0x12351993, 0xd9cbb01c,
    0x603147a2, 0xcf37d17d, 0xf7fcd9dc, 0xd8556fa3, 0x104c8131, 0x13152774, 0xb4715811, 0x6a72c2c9,
    0xc5ae37bb, 0xa76ce12a, 0x8150d8f3, 0x2ec29218, 0xa35f0984, 0x48c0647e, 0x0b5ff98c, 0x71893f7b
};

#define BARREL_SHIFT(v, shift) ( ((v) << shift) | ((v) >> (32 - shift)) )


static uint32_t * buzhash_init_table(uint32_t seed)
{
    int i;
    uint32_t *table = malloc(1024);
    for(i = 0; i < 256; i++)
    {
        table[i] = table_base[i] ^ seed;
    }
    return table;
}

static uint32_t buzhash(const unsigned char *data, size_t len, const uint32_t *h)
{
    uint32_t i;
    uint32_t sum = 0, imod;
    for(i = len - 1; i > 0; i--)
    {
        imod = i & 0x1f;
        sum ^= BARREL_SHIFT(h[*data], imod);
        data++;
    }
    return sum ^ h[*data];
}

static uint32_t buzhash_update(uint32_t sum, unsigned char remove, unsigned char add, size_t len, const uint32_t *h)
{
    uint32_t lenmod = len & 0x1f;
    return BARREL_SHIFT(sum, 1) ^ BARREL_SHIFT(h[remove], lenmod) ^ h[add];
}

Chunker * chunker_init(int window_size, int chunk_mask, int min_size, uint32_t seed)
{
    Chunker *c = calloc(sizeof(Chunker), 1);
    c->window_size = window_size;
    c->chunk_mask = chunk_mask;
    c->min_size = min_size;
    c->table = buzhash_init_table(seed);
    //c->buf_size = 10 * 1024 * 1024;
    c->buf_size = 1 * 1024 * 1024;
    c->data = malloc(c->buf_size);
    return c;
}

void chunker_set_fd(Chunker *c, int fd)
{
    c->fd = fd;
    c->done = 0;
    c->remaining = 0;
    c->bytes_read = 0;
    c->bytes_yielded = 0;
    c->position = 0;
    c->last = 0;
    c->eof = 0;
}

void chunker_free(Chunker *c)
{
    free(c->table);
    free(c->data);
    free(c);
}

static chunker_error_t chunker_fill(Chunker *c)
{
    size_t n;
    memmove(c->data, c->data + c->last, c->position + c->remaining - c->last);
    c->position -= c->last;
    c->last = 0;
    n = c->buf_size - c->position - c->remaining;
    if(c->eof || n == 0) {
        return CHUNKER_ERROR_NONE;
    }

    unsigned char * data = malloc(n);
    if (data == NULL) {
        return CHUNKER_ERROR_MEM_ALLOC;
    }
    int ret = read(c->fd, data, n);
    if (ret < 0) {
        free(data);
        return CHUNKER_ERROR_READ;
    }
    n = ret;
    if(n) {
        memcpy(c->data + c->position + c->remaining, data, n);
        c->remaining += n;
        c->bytes_read += n;
    }
    else {
        c->eof = 1;
    }
    free(data);
    return CHUNKER_ERROR_NONE;
}


// chunker_process returns a chunk each time it is called, or NULL when EOF or error
//static PyObject *
raw_chunk_w_size_t
chunker_process(Chunker *c)
{
    uint32_t sum, chunk_mask = c->chunk_mask, min_size = c->min_size, window_size = c->window_size;
    int n = 0;
    int old_last;
    raw_chunk_w_size_t return_chunk = { .data = NULL, .len = 0, .error = CHUNKER_ERROR_NONE};

    if(c->done) {
        if(c->bytes_read == c->bytes_yielded) {
            // no more data to process (was: StopIteration)
        }
        else {
            return_chunk.error = CHUNKER_ERROR_BYTE_COUNT_MISMATCH;
        }
        return return_chunk;
    }
    if(c->remaining <= window_size) {
        chunker_error_t ce = chunker_fill(c);
        if(ce != CHUNKER_ERROR_NONE) {
            return_chunk.error = ce;
            return return_chunk;
        }
    }
    if(c->remaining < window_size) {
        c->done = 1;
        if(c->remaining) {
            c->bytes_yielded += c->remaining;
            return_chunk.data = malloc(c->remaining);
            if (return_chunk.data == NULL) {
                return_chunk.error = CHUNKER_ERROR_MEM_ALLOC;
                return return_chunk;
            }
            memcpy(return_chunk.data, c->data + c->position, c->remaining);
            return_chunk.len = c->remaining;
            return return_chunk;
            //return PyBuffer_FromMemory(c->data + c->position, c->remaining);
        }
        else {
            if(c->bytes_read == c->bytes_yielded) {
                // no more data to process (was: StopIteration)
            }
            else {
                return_chunk.error = CHUNKER_ERROR_BYTE_COUNT_MISMATCH;
            }
            return return_chunk;
        }
    }
    sum = buzhash(c->data + c->position, window_size, c->table);
    while((ssize_t)c->remaining > c->window_size && ((sum & chunk_mask) || n < (int32_t)min_size)) {
        sum = buzhash_update(sum, c->data[c->position],
                             c->data[c->position + window_size],
                             window_size, c->table);
        c->position++;
        c->remaining--;
        n++;
        if(c->remaining <= window_size) {
            chunker_error_t ce = chunker_fill(c);
            if(ce != CHUNKER_ERROR_NONE) {
                return_chunk.error = ce;
                return return_chunk;
            }
        }
    }
    if(c->remaining <= window_size) {
        c->position += c->remaining;
        c->remaining = 0;
    }
    old_last = c->last;
    c->last = c->position;
    n = c->last - old_last;
    c->bytes_yielded += n;

    return_chunk.data = malloc(n);
    if (return_chunk.data == NULL) {
        return_chunk.error = CHUNKER_ERROR_MEM_ALLOC;
        return return_chunk;
    }
    memcpy(return_chunk.data, c->data + old_last, n);
    return_chunk.len = n;
    return return_chunk;
    //return PyBuffer_FromMemory(c->data + old_last, n);
}
