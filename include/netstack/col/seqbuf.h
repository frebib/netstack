#ifndef NETSTACK_SEQBUF_H
#define NETSTACK_SEQBUF_H

#include <stdint.h>


typedef struct seqbuf {
    struct seqbuf_block *head, *tail;
    size_t start;           // Sequence number of first byte in buffers->head
    size_t count;           // Number of bytes in all buffers, starting from
                            // start at the first byte of buffers->head
    size_t limit;           // Wrapping point in the buffer
} seqbuf_t;

struct seqbuf_block {
    struct seqbuf_block *next;
    size_t len;
    // Access the block payload with `block + 1`
};

int seqbuf_init(seqbuf_t *buf, size_t start, size_t limit);

void seqbuf_free(seqbuf_t *buf);

long seqbuf_read(seqbuf_t *buf, size_t from, void *dest, size_t len);

long seqbuf_write(seqbuf_t *buf, const void *src, size_t len);

int seqbuf_consume(seqbuf_t *buf, size_t from, size_t len);

int seqbuf_consume_to(seqbuf_t *buf, size_t newstart);

/*!
 * Returns the number of bytes available to read from the buffer starting at
 * (and including) from
 */
long seqbuf_available(seqbuf_t *buf, size_t from);


#endif //NETSTACK_SEQBUF_H
