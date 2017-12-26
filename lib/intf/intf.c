#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <pthread.h>

#include <netstack/eth/ether.h>
#include <netstack/ip/ipv4.h>
#include <netstack/intf/intf.h>

int intf_dispatch(struct frame *frame) {
    // Obtain the sendqlck
    pthread_mutex_lock(&frame->intf->sendqlck);
    // Push the frame into the queue
    queue_push(&frame->intf->sendq, frame);
    // Release the sendqlck
    pthread_mutex_unlock(&frame->intf->sendqlck);
    // Signal the sendctr sem
    sem_post(&frame->intf->sendctr);

    return 0;
}

struct frame *intf_frame_new(struct intf *intf, size_t buf_size) {
    void *buffer = NULL;
    if (buf_size > 0)
        buffer = intf->new_buffer(intf, buf_size);

    return frame_init(intf, buffer, buf_size);
}

void intf_frame_free(struct frame *frame) {
    if (frame->buffer) {
        if (frame->intf)
            frame->intf->free_buffer(frame->intf, frame->buffer);
        else
            fprintf(stderr, "Error: Frame has buffer (%lu bytes) but no intf",
                    frame->buf_size);
    }
    frame_free(frame);
}

void intf_frame_llist_clear(struct llist *list) {
    llist_iter(list, intf_frame_free);
    llist_clear(list);
}

void *intf_malloc_buffer(struct intf *intf, size_t size) {
    return malloc(size);
}

void intf_free_buffer(struct intf *intf, void *buffer) {
    free(buffer);
}


/*
 *  Send/Receive threads used internally in the interface
 */
void _intf_send_thread(struct intf *intf) {

    // Manually determine when the thread can be cancelled
    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);


    // Wait on the sendctr for something to send
    while (sem_wait(&intf->sendctr) == 0) {

        // Wait until send is complete before allowing cancellation
        pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

        pthread_mutex_lock(&intf->sendqlck);
        struct frame *frame = queue_pop(&intf->sendq);
        pthread_mutex_unlock(&intf->sendqlck);

        // Only attempt to send a non-null frame
        if (frame) {
            // Send the frame!
            long ret = intf->send_frame(frame);
            if (ret != 0)
                fprintf(stderr, "send_frame() returned %ld: %s",
                        ret, strerror( (int) ret));

            // TODO: Dispose of sent frame
            intf_frame_free(frame);
        }

        pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    }
}

void _intf_recv_thread(struct intf *intf) {
    struct frame *rawframe = NULL;
    ssize_t count;

    // Manually determine when the thread can be cancelled
    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

    rawframe = intf_frame_new(intf, 0);

    while ((count = intf->recv_frame(rawframe)) != -1) {
        // Capture time as packet is read
        struct timespec ts;
        // TODO: Implement rx 'software' timestamping
        if (false) {
            timespec_get(&ts, TIME_UTC);
        } else {
            ts = rawframe->time;
        }

        // TODO: Use logging
        // TODO: Conditionally print debugging information
        // Format and print time the same as tcpdump for comparison
        char buf[20];
        strftime(buf, sizeof(buf), "%T", gmtime(&ts.tv_sec));
        snprintf(buf + 8, 11, ".%09ld", ts.tv_nsec);
        buf[15] = '\0'; // Manually truncate nanoseconds to 6 chars long
        printf("%s ", buf);

        // Push received data into the stack
        switch (intf->proto) {
            case PROTO_ETHER:
                ether_recv(rawframe);
                break;
            case PROTO_IP:
            case PROTO_IPV4:
                ipv4_recv(rawframe);
                break;
            default:
                fprintf(stderr, "Interface protocol %d unsupported\t",
                        intf->proto);
                break;
        }

        printf("\n");
        fflush(stdout);

        // Allocate a new frame
        intf_frame_free(rawframe);
        rawframe = NULL;

        // Check if the thread should exit
        pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
        pthread_testcancel();
        pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

        rawframe = intf_frame_new(intf, 0);
    }

    if (count == -1) {
        perror("recv error");
    }
}

int pthread_create_named(pthread_t *id, char *name,
                         void (*fn)(struct intf *), void *arg) {
    // Create and start thread
    int ret = pthread_create(id, NULL, (void *(*)(void *)) fn, arg);
#ifdef _GNU_SOURCE
    // Set the thread name, if available
    pthread_setname_np(*id, name);
#endif

    return ret;
}

int intf_init(struct intf *intf) {
    if (intf == NULL) {
        errno = EINVAL;
        return -1;
    }

    /* Create a semaphore for locking the send queue */
    sem_init(&intf->sendctr, 0, 0);
    pthread_mutex_init(&intf->sendqlck, NULL);

    intf->arptbl = (struct llist) LLIST_INITIALISER;
    intf->sendq = (struct llist) LLIST_INITIALISER;

    printf("Creating threads\n");

    // Create threads
    pthread_t *th_ids = intf->threads;
    pthread_create_named(&th_ids[INTF_THR_SEND], "send",
                         &_intf_send_thread, intf);
    pthread_create_named(&th_ids[INTF_THR_RECV], "recv",
                         &_intf_recv_thread, intf);

    return 0;
}

size_t intf_max_frame_size(struct intf *intf) {
    // TODO: Check intf hwtype to calculate max frame size
    return intf == NULL ? 0 : intf->mtu + sizeof(struct eth_hdr);
}

bool intf_has_addr(struct intf *intf, addr_t *addr) {
    if (addr->proto == 0) {
        fprintf(stderr, "Error: intf_has_addr() called with empty protocol\n");
        return false;
    }

    for_each_llist(&intf->inet) {
        addr_t *intf_addr = llist_elem_data();
        if (addreq(intf_addr, addr))
            return true;
    }
    return false;
}

bool intf_get_addr(struct intf *intf, addr_t *addr) {
    if (addr->proto == 0) {
        fprintf(stderr, "Error: intf_get_addr() called with empty protocol\n");
        return false;
    }

    for_each_llist(&intf->inet) {
        addr_t *intf_addr = llist_elem_data();
        // TODO: Selectively choose an appropriate address from intf
        // for now just use the first with a matching protocol
        if (addr->proto == intf_addr->proto) {
            memcpy(addr, intf_addr, sizeof(addr_t));
            return true;
        }
    }
    return false;
}
