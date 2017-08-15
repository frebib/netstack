#include <libnet/frame.h>
#include <string.h>
#include <stdio.h>

struct frame *init_frame(struct sock *sock, size_t size) {
    struct frame *frame = malloc(sizeof(struct frame));
    if (size > 0) {
        frame->buffer = malloc(size);
        frame->buf_size = size;
    } else {
        frame->buffer = NULL;
    }
    frame->head = frame->buffer;
    frame->data = frame->head;
    frame->tail = frame->buffer + size;
    frame->sock = sock;
    frame->parent = frame->child = NULL;

    return frame;
}

void free_frame(struct frame *frame) {
    // free() performs the null check for us
    if (frame->parent == NULL) {
        // Only free the buffer if we created it!
        free(frame->buffer);
    }
    // Iterate through children only, we want to keep the parents
    struct frame* child;
    do {
        child = frame->child;
        free(frame);
        frame = child;
    } while (child != NULL);
}

struct frame *frame_child_copy(struct frame *parent) {
    if (parent == NULL) {
        return NULL;
    }

    struct frame *child = malloc(FRAME_LEN);
    memcpy(child, parent, FRAME_LEN);

    parent->child = child;
    child->parent = parent;
    child->head = parent->data;
    child->data = child->head;

    return child;
}

