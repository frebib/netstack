#include <string.h>
#include <malloc.h>
#include <errno.h>

#define NETSTACK_LOG_UNIT "FRAME"
#include <netstack/log.h>
#include <netstack/frame.h>

struct frame *frame_init(struct intf *intf, void *buffer, size_t buf_size) {
    struct frame *frame = calloc(1, sizeof(struct frame));
    frame->intf = intf;
    if (buffer != NULL)
        frame_init_buf(frame, buffer, buf_size);

    // Allocate space for 4 protocol layers by default
    alist_init(&frame->layer, 4);
    atomic_init(&frame->refcount, 1);

    pthread_rwlock_init(&frame->lock, NULL);
    frame_lock(frame, SHARED_RW);

    return frame;
}

struct frame *frame_clone(struct frame *orig, enum shared_mode mode) {
    if (orig == NULL) {
        return NULL;
    }

    struct frame *clone = calloc(1, sizeof(struct frame));
    memcpy(clone, orig, sizeof(struct frame));
    // Clones don't have the buffer ptr, this prevents them free'ing it
    clone->buffer = NULL;
    clone->buf_sz = 0;

    // Allocate and copy the protocol stack arraylist
    alist_lock(&orig->layer);
    clone->layer.arr = malloc(orig->layer.len);
    memcpy(clone->layer.arr, orig->layer.arr, orig->layer.len);
    alist_unlock(&orig->layer);

    // Clones have their own refcount
    atomic_init(&clone->refcount, 1);

    pthread_rwlock_init(&clone->lock, NULL);
    frame_lock(clone, mode);

    return clone;
}

void frame_init_buf(struct frame *frame, void *buffer, size_t buf_size) {
    frame->buffer = buffer;
    frame->buf_sz = buf_size;
    frame->head = frame->buffer;
    frame->tail = frame->buffer + buf_size;
    frame->data = frame->tail;
}

void frame_decref(struct frame *frame) {
    if (frame == NULL)
        return;

    // Subtract and check old value
    if (atomic_fetch_sub(&frame->refcount, 1) == 1) {
        // refcount hit 0. Deallocate frame memory
        if (frame->buffer != NULL)
            frame->intf->free_buffer(frame->intf, frame->buffer);
        alist_free(&frame->layer);
        // Unlock before free'ing
        frame_unlock(frame);
        // If another thread gains access here, after unlocking, it is a bug
        // That thread needs to be holding a reference to prevent deallocation
        free(frame);
    }
}

// TODO: Deduplicate frame_decref_unlock() code
void frame_decref_unlock(struct frame *frame) {
    if (frame == NULL)
        return;

    // Subtract and check old value
    if (atomic_fetch_sub(&frame->refcount, 1) == 1) {
        // refcount hit 0. Deallocate frame memory
        if (frame->buffer != NULL)
            frame->intf->free_buffer(frame->intf, frame->buffer);
        alist_free(&frame->layer);
        // Unlock before free'ing
        frame_unlock(frame);
        // If another thread gains access here, after unlocking, it is a bug
        // That thread needs to be holding a reference to prevent deallocation
        free(frame);
    } else {
        // Unlock anyway
        frame_unlock(frame);
    }
}

int frame_layer_push_ptr(struct frame *f, proto_t prot, void *hdr, void *data) {
    if (f == NULL || prot == 0 || hdr == NULL)
        return -EINVAL;

    struct frame_layer *elem;
    int ret;
    if ((ret = alist_add(&f->layer, (void **) &elem)))
        return ret;

    elem->proto = prot;
    elem->hdr   = hdr;
    elem->data  = data;

    return 0;
}

struct frame_layer *frame_layer_outer(struct frame *frame, uint8_t rel) {
    // Ensure relative position is within the bounds of the elements in the arr
    if (((int8_t) frame->layer.count - rel) < 0)
        return NULL;

    // Index the layer array for a relative frame from the end
    // This assumes there are no gaps in the array elements
    struct frame_layer *layer = &frame->layer.arr[frame->layer.count - 1 - rel];
    return (layer->proto == 0) ? NULL : layer;
}
