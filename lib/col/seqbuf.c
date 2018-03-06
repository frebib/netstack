#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <sys/param.h>

#define NETSTACK_LOG_UNIT "SEQBUF"
#include <netstack/log.h>
#include <netstack/col/seqbuf.h>

int seqbuf_init(seqbuf_t *buf, size_t start) {
    if (buf == NULL)
        return -EINVAL;

    buf->head = NULL;
    buf->tail = NULL;
    buf->start = start;
    buf->count = 0;

    return 0;
}

void seqbuf_free(seqbuf_t *buf) {
    if (buf != NULL) {

        struct seqbuf_block *cur, *block = buf->head;
        while (block != NULL) {
            cur = block;
            block = block->next;
            free(cur);
        }

        buf->count = 0;
        buf->start = 0;
    }
}

long seqbuf_read(seqbuf_t *buf, size_t from, void *dest, size_t len) {
    if (buf == NULL)
        return -EINVAL;

    long avail = seqbuf_available(buf, from);
    if (avail <= 0)
        return avail;

    // We can only read at most what is available, or what is requested
    size_t toread = MIN(len, avail);
    // Offset by the initial byte
    size_t blockofs = from - buf->start;
    // Cumulative sum of bytes read
    size_t total_read = 0;
    // Start at the first buffer and advance from there
    struct seqbuf_block *block = buf->head;

    // Advance blocks until the offset resides within the block
    while (blockofs > block->len) {

        blockofs -= block->len;
        block = block->next;

        // The next block doesn't exist (this shouldn't ever happen)
        if (block == NULL) {
            LOG(LERR, "buffer doesn't exist but it should.");
            return -1;
        }
    }

    // TODO: Try mmap() buffers into one contiguous region with one memcpy call

    while (total_read < toread && block != NULL) {

        void *data = block + 1;
        size_t left_in_block = MIN(toread - total_read, block->len - blockofs);

        // Read up to the end of the current buffer
        memcpy(dest + total_read, data + blockofs, left_in_block);

        // Advance counters and pointers
        total_read += left_in_block;
        // Offset within each buffer frame. mod bufsize prevents over-reading
        blockofs = (blockofs + total_read) % block->len;

        block = block->next;
    }

    return total_read;
}

long seqbuf_write(seqbuf_t *buf, void *src, size_t len) {
    if (buf == NULL)
        return -EINVAL;

    struct seqbuf_block *block;

    // Allocate a new buffer to write the entire segment into
    block = malloc(sizeof(struct seqbuf_block) + len);
    if (block == NULL)
        return -ENOMEM;

    // Copy the data into it
    void *data = block + 1;
    memcpy(data, src, len);

    // Update the buffer size
    buf->count += len;

    // There are no blocks in the buffer, this is the first
    if (buf->head == NULL)
        buf->head = block;
    else
        buf->tail->next = block;

    block->len = len;
    block->next = NULL;
    // The tail of the buffer is always the newest block
    buf->tail = block;

    LOG(LINFO, "added new seqbuf block %p, %zu bytes, %zu total",
        block, len, buf->count);

    return len;
}

int seqbuf_consume(seqbuf_t *buf, size_t from, size_t len) {
    if (buf == NULL)
        return -EINVAL;

    if (from < buf->start) {
        LOG(LERR, "from (%zu) < buf->start (%zu)", from, buf->start);
        return -EOVERFLOW;
    }
    if ((buf->count - from - buf->start) < len) {
        LOG(LERR, "len (%zu) > buf->count (%zu), from %zu", len, buf->count, from);
        return -ERANGE;
    }

    LOG(LTRCE, "consuming %ld bytes from %zu (out of %ld)", len, from, buf->count);

    size_t blocksize = buf->head->len - (from - buf->start);

    while (len >= blocksize) {

        // Update # of bytes left to remove
        len -= blocksize;

        // Move the start to the next unconsumed block
        buf->start += blocksize;
        buf->count -= blocksize;

        // Store the old head so we can update the new one
        void *tofree = buf->head;

        // Update the head to the next block before free'ing the pointer
        buf->head = buf->head->next;

        free(tofree);

        // We've free'd every block. We're done now
        if (buf->head == NULL)
            break;

        // Update the blocksize for the next iteration if buf->head isn't NULL
        blocksize = buf->head->len;
    }

    if (buf->head == NULL)
        buf->tail = NULL;

    return 0;
}

int seqbuf_consume_to(seqbuf_t *buf, size_t newstart) {
    if (buf == NULL)
        return -EINVAL;

    long diff = (long) (newstart - buf->start);

    if (diff < 0) {
        LOG(LNTCE, "consume_to(%zu) is %ld before current %zu",
            newstart, -diff, buf->start);
        return -ERANGE;
    } if (diff <= 0)
        return 0;

    return seqbuf_consume(buf, buf->start, (newstart - buf->start));
}

long seqbuf_available(seqbuf_t *buf, size_t from) {
    if (buf == NULL)
        return -EINVAL;

    if (from < buf->start) {
        LOG(LERR, "from (%zu) < buf->start (%zu)", from, buf->start);
        return 0;
    }

    // Only return >= 0 available bytes
    return MAX((long) (buf->start + buf->count - from), 0);
}
