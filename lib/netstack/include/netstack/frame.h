#ifndef NETSTACK_FRAME_H
#define NETSTACK_FRAME_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <netstack/socket.h>

#define FRAME_LEN sizeof(struct frame)

struct frame {
    struct sock *sock;
    size_t buf_size;
    struct timespec time;   /* Send/recv time for frame */
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
struct frame *frame_init(struct sock *sock, size_t size);

/* Frees a frame and it's enclosed buffer */
void frame_free(struct frame *frame);

/* Clones a frame, setting it's child to the clone and the parent of the
 * child to the original frame. Returns the new child frame */
struct frame *frame_child_copy(struct frame *parent);

#endif //NETSTACK_FRAME_H
