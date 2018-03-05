#ifndef NETSTACK_SEQBUF_H
#define NETSTACK_SEQBUF_H

#include <stdint.h>

#include <netstack/col/llist.h>


typedef struct seqbuf {
    llist_t buffers;
    size_t bufsize;         // Fixed size of all memory buffers
    size_t start;           // Sequence number of first byte in buffers->head
    size_t count;           // Number of bytes in all buffers, starting from
                            // start at the first byte of buffers->head
} seqbuf_t;


int seqbuf_init(seqbuf_t *buf, size_t bufsize, size_t start);

void seqbuf_free(seqbuf_t *buf);

long seqbuf_read(seqbuf_t *buf, size_t from, void *dest, size_t len);

long seqbuf_write(seqbuf_t *buf, void *src, size_t len);

void seqbuf_consume(seqbuf_t *buf, size_t len);

void seqbuf_consume_to(seqbuf_t *buf, size_t newstart);

/*!
 * Returns the number of bytes available to read from the buffer starting at
 * (and including) from
 */
long seqbuf_available(seqbuf_t *buf, size_t from);


#endif //NETSTACK_SEQBUF_H
