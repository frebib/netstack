#ifndef NETD_FRAME_H
#define NETD_FRAME_H

#include <stdint.h>
#include <gdcache.h>
#include <libnet/socket.h>

#define FRAME_LEN sizeof(struct frame)

struct frame {
    struct sock *sock;
    size_t buf_size;
    uint8_t *buffer,
            *head,
            *data,
            *tail;

    struct frame *parent,
                 *child;
};

/* Initialises a new frame on the heap,
   with a buffer if a size is provided,
   linked to an optional socket */
struct frame *init_frame(struct sock *sock, size_t size);

/* Frees a frame and it's enclosed buffer */
void free_frame(struct frame *frame);

/* Clones a frame, setting it's child to the clone and the parent of the
 * child to the original frame. Returns the new child frame */
struct frame *frame_child_copy(struct frame *parent);

#endif //NETD_FRAME_H
