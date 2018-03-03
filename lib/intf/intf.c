#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <pthread.h>

#define NETSTACK_LOG_UNIT "INTF"
#include <netstack/log.h>
#include <netstack/eth/ether.h>
#include <netstack/ip/ipv4.h>


// Private functions
void _intf_recv_thread(struct intf *intf);


int intf_dispatch(struct frame *frame) {
    // Send the frame
    long ret = frame->intf->send_frame(frame);

    // Log outgoing packets
    struct pkt_log log = PKT_TRANS(LFRAME);

    switch (frame->intf->proto) {
        case PROTO_ETHER:
            LOGT_OPT_COMMIT(ether_log(&log, frame), &log.t);
            break;
        case PROTO_IP:
        case PROTO_IPV4:
            LOGT_OPT_COMMIT(ipv4_log(&log, frame), &log.t);
            break;
        default:
            break;
    }

    return (int) ((ret < 0) ? ret : 0);
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
 *  Receive thread used internally in the interface
 */
void _intf_recv_thread(struct intf *intf) {
    struct frame *rawframe = NULL;
    ssize_t count;

    // Manually determine when the thread can be cancelled
    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

    rawframe = intf_frame_new(intf, 0);

    while ((count = intf->recv_frame(rawframe)) != -1) {
        // TODO: Implement rx 'software' timestamping

        if (count < 1) {
            LOG(LERR, "interface returned an empty frame");
            continue;
        }
        if (rawframe->buffer == NULL || rawframe->buf_sz < 1) {
            LOG(LERR, "recv'd frame has no data");
            continue;
        }

        // Use transactional logging for packet logs
        struct frame *logframe = frame_clone(rawframe, SHARED_RD);
        struct pkt_log log = PKT_TRANS(LFRAME);
        memcpy(&log.t.time, &rawframe->time, sizeof(struct timespec));

        // Release write lock: *_recv functions are read-only
        frame_unlock(rawframe);
        frame_lock(rawframe, SHARED_RD);

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

        // Decref and unlock logframe
        frame_decref_unlock(logframe);

        // Decrement frame refcount and unlock it regardless
        frame_decref_unlock(rawframe);
        rawframe = NULL;

        // Check if the thread should exit
        pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
        pthread_testcancel();
        pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

        // Allocate a new frame
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
    if (intf == NULL)
        return EINVAL;

    intf->arptbl = (llist_t) LLIST_INITIALISER;

    LOG(LDBUG, "Creating threads");

    // Concatenate interface name before thread name
    size_t len = 32;
    char temp[strlen(intf->name) + len];
    int end = snprintf(temp, len, "%s/", intf->name);
    // Create threads
    pthread_t *th_ids = intf->threads;
    pthread_create_named(&th_ids[INTF_THR_RECV], strncat(temp, "rcv", len),
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

    pthread_mutex_lock(&intf->inet.lock);
    for_each_llist(&intf->inet) {
        addr_t *intf_addr = llist_elem_data();
        if (addreq(intf_addr, addr)) {
            pthread_mutex_unlock(&intf->inet.lock);
            return true;
        }
    }
    pthread_mutex_unlock(&intf->inet.lock);
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
