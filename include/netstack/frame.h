#ifndef NETSTACK_FRAME_H
#define NETSTACK_FRAME_H

#include <stdint.h>
#include <stddef.h>
#include <stdatomic.h>
#include <time.h>
#include <netstack/inet.h>
#include <netstack/proto.h>
#include <netstack/col/alist.h>
#include <netstack/intf/intf.h>
#include <netstack/lock/shared.h>

// Fix circular include issue
struct intf;


/*
 * List of protocol layers found in a frame
 * The list is strictly ordered by appearance within the frame
 */
struct frame_layer {
    proto_t proto;
    void *hdr;
    void *data;
};
ARRAYLIST_DEFINE(frame_stack, struct frame_layer);


/*
 * A frame is ALWAYS stored in network byte order
 */

struct frame {
    struct intf *intf;      /* Always present for incoming packets */
    addr_t   locaddr;
    addr_t   remaddr;
    uint16_t locport;
    uint16_t remport;

    struct timespec time;   /* Send/recv time for frame */
    frame_stack_t layer;    /* Arraylist of protocol layers in frame, ordered */
    size_t buf_sz;
    uint8_t *buffer,        /* These pointers are for 'current use' only.
                               refer to proto[] for list of protocol ptrs */
            *head,          /* It cannot be assumed that head and data */
            *data,          /* are a contiguous region of memory */
            *tail;

    pthread_rwlock_t lock;
    atomic_uint refcount;
};


/*!
 * Shifts the head and data pointers backwards by size
 */
#define frame_data_alloc(frame, size) \
        (void *) ((frame)->head = (frame)->data -= (size))

/*!
 * Sets the data pointer to head then shifts head back by size
 */
#define frame_head_alloc(frame, size) \
        (void *) ((frame)->head = ((frame)->data = (frame)->head) - (size))

/*!
 * Calculates the total length of the frame header and payload
 * */
#define frame_pkt_len(frame) (uint16_t) ((frame)->tail - (frame)->head)

/*!
 * Calculates the total length of the frame header
 */
#define frame_hdr_len(frame) (uint16_t) ((frame)->data - (frame)->head)

/*!
 * Calculates the total length of the frame payload
 */
#define frame_data_len(frame) (uint16_t) ((frame)->tail - (frame)->data)


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
void frame_init_buf(struct frame *frame, void *buffer, size_t buf_size);

/*!
 * Increases the reference count for a frame, preventing it from being
 * deallocated prematurely. To release the reference, call frame_decref()
 * Note: There is no requirement to hold frame->lock as this operation is atomic
 */
#define frame_incref(frame) atomic_fetch_add(&(frame)->refcount, 1)

/*!
 * Indicates the frame is no longer required.
 * If refcount hits zero, the frame and buffer is free'd
 *    Whoever creates a frame is responsible for dereferencing it.
 *    When a frame is passed to any internal code, it can be assumed that any
 *    required references will be added. Any dangling frames will cause
 *    memory leaks!
 * Only releases the frame->lock if the frame is to be deallocated
 * Note: The shared frame->lock should be held before calling this
 * @param frame frame to dereference
 */
uint frame_decref(struct frame *frame);

/*!
 * Performs the same action as frame_decref() but
 * ALWAYS releases the frame->lock
 */
uint frame_decref_unlock(struct frame *frame);

/*!
 * Clones a frame
 * A clone has:
 *    Its own lock
 *    Its own refcount
 *    No buffer, so that it cannot be free'd
 *    A copied frame-stack (independent from original frame)
 * @param orig frame to clone
 */
struct frame *frame_clone(struct frame *orig, enum shared_mode mode);

/*!
 * Obtains the frame mutex lock to prevent simultaneous access
 * @param type  lock for reading or reading/writing
 * @return see pthread_mutex_lock(3P)
 */
#define frame_lock(frame, type) shared_lock(&(frame)->lock, (type))

/*!
 * Releases the frame mutex lock
 * @return see pthread_mutex_lock(3P)
 */
#define frame_unlock(frame) shared_unlock(&(frame)->lock)

/*!
 * Pushes a protocol into the frame protocol stack
 * @param frame  frame to add protocol to
 * @param proto  protocol to add
 * @param hdr    pointer to protocol header
 * @param data   pointer to protocol data
 * @return 0 on success, negative on error
 */
int frame_layer_push_ptr(struct frame *f, proto_t prot, void *hdr, void *data);

/*!
 * Performs the same operation as frame_layer_push_ptr() but
 * assumes hdr and data pointers are frame->head and frame->data respectively
 */
#define frame_layer_push(frame, proto) \
        frame_layer_push_ptr((frame), (proto), (frame)->head, (frame)->data)

/*!
 * Finds the nth outer frame_layer
 * @param frame frame to search
 * @param rel relative index of frame layer
 *            values are relative from the inner-most layer
 *            0 is the inner-most layer, 1 is the parent of that etc.
 * @return a pointer to a frame_layer, or NULL if not found
 */
struct frame_layer *frame_layer_outer(struct frame *frame, uint8_t rel);

#endif //NETSTACK_FRAME_H
