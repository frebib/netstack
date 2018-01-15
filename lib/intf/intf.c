#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <pthread.h>

#include <netstack/log.h>
#include <netstack/eth/ether.h>
#include <netstack/ip/ipv4.h>

int intf_dispatch(struct frame *frame) {
    // Ensure send() has a reference, keeping the frame alive
    frame_incref(frame);

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
            int ret = (int) intf->send_frame(frame);
            if (ret != 0)
                LOG(LINFO, "send_frame() returned %ld: %s", ret, strerror(ret));

            // Log outgoing packets
            struct pkt_log log = PKT_TRANS(LFRAME);
            bool should_print = false;

            switch (intf->proto) {
                case PROTO_ETHER:
                    should_print = ether_log(&log, frame);
                    break;
                case PROTO_IP:
                case PROTO_IPV4:
                    should_print = ipv4_log(&log, frame);
                    break;
                default:
                    break;
            }
            if (should_print)
                LOGT_COMMIT(&log.t);
            else
                LOGT_DISPOSE(&log.t);

            // Frame sent, disown it
            frame_deref(frame);
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
        // TODO: Implement rx 'software' timestamping

        // Use transactional logging for packet logs
        struct frame *logframe = frame_clone(rawframe);
        struct pkt_log log = PKT_TRANS(LFRAME);
        memcpy(&log.t.time, &rawframe->time, sizeof(struct timespec));

        // TODO: Conditionally print debugging information
        // Push received data into the stack
        switch (intf->proto) {
            case PROTO_ETHER:
                LOGT_OPT_COMMIT(ether_log(&log, logframe), &log.t);
                ether_recv(rawframe);
                break;
            case PROTO_IP:
            case PROTO_IPV4:
                LOGT_OPT_COMMIT(ipv4_log(&log, logframe), &log.t);
                ipv4_recv(rawframe);
                break;
            default:
                LOG(LWARN, "Interface protocol %d unsupported\t", intf->proto);
                break;
        }

        // TODO: Use same frame stack instead of cloning across threads
        // Call frame_free() to ensure cloned frames are destroyed.
        // frame_deref() won't free cloned frames here because the buffer is
        // still referenced in rawframe.
        frame_deref(logframe);
        frame_free(logframe);

        // Allocate a new frame
        frame_deref(rawframe);
        rawframe = NULL;

        // Check if the thread should exit
        pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
        pthread_testcancel();
        pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

        rawframe = intf_frame_new(intf, 0);
    }

    if (count == -1) {
        LOGERR("recv");
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

    LOG(LDBUG, "Creating threads\n");

    // Concatenate interface name before thread name
    size_t len = 32;
    char temp[strlen(intf->name) + len];
    int end = snprintf(temp, len, "%s/", intf->name);
    // Create threads
    pthread_t *th_ids = intf->threads;
    pthread_create_named(&th_ids[INTF_THR_SEND], strncat(temp, "send", len),
                         &_intf_send_thread, intf);
    temp[end] = '\0';   // Reset string end
    pthread_create_named(&th_ids[INTF_THR_RECV], strncat(temp, "recv", len),
                         &_intf_recv_thread, intf);
    temp[end] = '\0';

    return 0;
}

size_t intf_max_frame_size(struct intf *intf) {
    // TODO: Check intf hwtype to calculate max frame size
    return intf == NULL ? 0 : intf->mtu + sizeof(struct eth_hdr);
}

bool intf_has_addr(struct intf *intf, addr_t *addr) {
    if (addr->proto == 0) {
        LOG(LERR, "intf_has_addr() called with empty protocol");
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
        LOG(LERR, "intf_get_addr() called with empty protocol");
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
