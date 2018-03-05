#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <sys/param.h>

#define NETSTACK_LOG_UNIT "SEQBUF"
#include <netstack/log.h>
#include <netstack/col/seqbuf.h>

int seqbuf_init(seqbuf_t *buf, size_t bufsize, size_t start) {
    if (buf == NULL)
        return -EINVAL;

    buf->buffers = (llist_t) LLIST_INITIALISER;
    buf->bufsize = bufsize;
    buf->start = start;
    buf->count = 0;

    return 0;
}

void seqbuf_free(seqbuf_t *buf) {
    if (buf != NULL) {
        llist_iter(&buf->buffers, free);
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
    size_t bufofs = from - buf->start;
    // Cumulative sum of bytes read
    size_t total = 0;
    // Start at the first buffer and advance from there
    struct llist_elem *elem = buf->buffers.head;

    // Advance buffers until we reach the first one we need
    while (bufofs > buf->bufsize) {
        // The next buffer doesn't exist (this shouldn't ever happen)
        if (elem == NULL) {
            LOG(LERR, "buffer doesn't exist but it should.");
            return -1;
        }
        elem = elem->next;
        bufofs -= buf->bufsize;
    }

    // TODO: Try mmap() buffers into one contiguous region with one memcpy call

    while (total < toread && elem != NULL) {
        void *src = elem->data;

        // Read up to the end of the current buffer
        size_t left = MIN(toread - total, buf->bufsize - bufofs);
        memcpy(dest + total, src + bufofs, left);

        // Advance counters and pointers
        total += left;
        elem = elem->next;
        // Offset within each buffer frame. mod bufsize prevents over-reading
        bufofs = (bufofs + total) % buf->bufsize;
    }

    return total;
}

long seqbuf_write(seqbuf_t *buf, void *src, size_t len) {
    if (buf == NULL)
        return -EINVAL;

    // We can only read at most what is available, or what is requested
    size_t written = 0;

    // Write at count, offset by start position
    size_t bufofs = buf->count;
    struct llist_elem *elem = buf->buffers.head;

    // Advance buffers until we reach the first one we need
    while (bufofs > buf->bufsize) {
        // The next buffer doesn't exist yet. Allocate it
        if (elem == NULL) {
            void *data = malloc(buf->bufsize);
            if (data == NULL)
                return -ENOMEM;

            llist_append_nolock(&buf->buffers, data);
            // The new buffer is the last one
            elem = buf->buffers.tail;
        } else {
            elem = elem->next;
        }
        bufofs -= buf->bufsize;
    }

    while (written < len) {
        if (elem == NULL) {
            // If we're out of buffers to write to, add another one
            void *data = malloc(buf->bufsize);
            if (data == NULL)
                return -ENOMEM;

            llist_append_nolock(&buf->buffers, data);
            // The new buffer is the last one
            elem = buf->buffers.tail;
        }
        void *dest = elem->data;

        // Write up to the end of the current buffer
        size_t left = len - written;
        size_t tocopy = MIN(left, buf->bufsize - bufofs);
        memcpy(dest + bufofs, src + written, tocopy);

        // Advance counters and pointers
        written += tocopy;
        buf->count += tocopy;
        elem = elem->next;
        // Offset within each buffer frame. mod bufsize prevents over-reading
        bufofs = buf->count % buf->bufsize;
    }

    return written;
}

void seqbuf_consume(seqbuf_t *buf, size_t len) {
    if (buf == NULL)
        return;

    // Move the start to the next unconsumed byte
    buf->start += len;
    buf->count -= len;

    // len is now # of iterations
    len /= buf->bufsize;

    // Remove whole buffers
    while (len-- > 0)
        free(llist_pop_nolock(&buf->buffers));
}

void seqbuf_consume_to(seqbuf_t *buf, size_t newstart) {
    if (buf == NULL)
        return;

    long diff = (long) (newstart - buf->start);

    if (diff <= 0) {
        if (diff < 0)
            LOG(LERR, "consume_to(%zu) is %ld before current %zu",
                newstart, -diff, buf->start);
        return;
    }

    LOG(LTRCE, "consuming bytes: %ld", diff);

    // Move the start to the next unconsumed byte
    buf->start = newstart;
    buf->count -= diff;

    diff /= buf->bufsize;

    // Remove whole buffers
    while (diff-- > 0)
        free(llist_pop_nolock(&buf->buffers));
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
