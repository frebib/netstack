#ifndef NETSTACK_FRAME_H
#define NETSTACK_FRAME_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <netstack/intf/intf.h>

// Fix circular include issue
struct intf;

struct frame {
    struct intf *intf;      /* Always present for incoming packets*/
    size_t buf_size;
    struct timespec time;   /* Send/recv time for frame */
    uint8_t *buffer,
            *head,          /* It cannot be assumed that head and data */
            *data,          /* are a contiguous region of memory */
            *tail;

    struct frame *parent,
                 *child;
};

/* Initialises a new frame on the heap,
   with a buffer if a size is provided,
   linked to an optional socket */

/*!
 * Initialises a new frame, allocating it using calloc(3)
 * @param intf      interface for recv'd packets (required) or for packets to
 *                  be sent (sometimes required)
 * @param buffer    allocated space for frame contents. Can be re-initialised
 *                  later with frame_init_buf() (optional)
 * @param buf_size  size of allocated buffer in octets (required with buffer)
 * @return          a new calloc(3)'ed frame, initialised
 */
struct frame *frame_init(struct intf *intf, void *buffer, size_t buf_size);

/*!
 * Initialises the frame buffer & sets head, tail and data pointers. data is
 * set to the tail of the buffer for pushing protocol headers bottom-up
 * @param frame     frame to add buffer to
 * @param buffer    allocated space for frame contents (required)
 * @param buf_size  size of allocated buffer in octets (required)
 */
void frame_init_buf(struct frame* frame, void *buffer, size_t buf_size);

/* Frees a frame and it's enclosed buffer */
void frame_free(struct frame *frame);

/* Clones a frame, setting it's child to the clone and the parent of the
 * child to the original frame. Returns the new child frame */
struct frame *frame_child_copy(struct frame *parent);

#endif //NETSTACK_FRAME_H
