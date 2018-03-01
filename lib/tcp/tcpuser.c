#include <stdlib.h>
#include <errno.h>
#include <netinet/in.h>

#include <netstack/tcp/tcp.h>
#include <netstack/lock/retlock.h>

/*
 * As defined in RFC 793: Functional Specification (pg 54 - 64)
 * https://tools.ietf.org/html/rfc793#page-54
 */

// TODO: Handle sending SIGPIPE for dead connections to calling process

/*
 * Follows OPEN Call: CLOSED STATE
 */
int tcp_user_open(struct tcp_sock *sock) {
    /*
      Create a new transmission control block (TCB) to hold connection
      state information.  Fill in local socket identifier, foreign
      socket, precedence, security/compartment, and user timeout
      information.  Note that some parts of the foreign socket may be
      unspecified in a passive OPEN and are to be filled in by the
      parameters of the incoming SYN segment.  Verify the security and
      precedence requested are allowed for this user, if not return
      "error:  precedence not allowed" or "error:  security/compartment
      not allowed."  If passive enter the LISTEN state and return.  If
      active and the foreign socket is unspecified, return "error:
      foreign socket unspecified"; if active and the foreign socket is
      specified, issue a SYN segment.  An initial send sequence number
      (ISS) is selected.  A SYN segment of the form <SEQ=ISS><CTL=SYN>
      is sent.  Set SND.UNA to ISS, SND.NXT to ISS+1, enter SYN-SENT
      state, and return.
    */

    if (sock == NULL)
        return -ENOTSOCK;

    // Ensure socket cannot be free'd until this lock is released
    tcp_sock_lock(sock);
    tcp_sock_incref(sock);

    switch (sock->state) {
        case TCP_ESTABLISHED:
        case TCP_FIN_WAIT_1:
        case TCP_FIN_WAIT_2:
        case TCP_LAST_ACK:
        case TCP_CLOSING:
        case TCP_CLOSE_WAIT:
            LOGFN(LNTCE, "tcp_sock_decref() because EISCONN");
            tcp_sock_decref_unlock(sock);
            return -EISCONN;
        case TCP_SYN_SENT:
        case TCP_SYN_RECEIVED:
            LOGFN(LNTCE, "tcp_sock_decref() because EALREADY");
            tcp_sock_decref_unlock(sock);
            return -EALREADY;
        default:
            break;
    }

    sock->inet.locport = tcp_randomport();
    // TODO: Fill out 'user timeout' information

    uint32_t iss = tcp_seqnum();
    sock->tcb.iss = iss;
    sock->tcb.snd.una = iss;
    sock->tcb.snd.nxt = iss + 1;
    sock->tcb.rcv.wnd = UINT16_MAX;

    int ret;
    if ((ret = tcp_send_syn(sock)) < 0) {
        LOGFN(LNTCE, "tcp_sock_decref() because tcp_send_syn() err");
        tcp_sock_decref_unlock(sock);
        return ret;
    }

    tcp_setstate(sock, TCP_SYN_SENT);

    // Wait for the connection to be established
    while (sock->state != TCP_ESTABLISHED && ret >= 0) {

        // Take reference to wait before releasing lock
        // Hopefully this does not incur a race condition :/
        retlock_t *wait = &sock->wait;
        // Unlock before going to sleep
        tcp_sock_unlock(sock);

        // TODO: Check for O_NONBLOCK
        if (false) {
            // TODO: Obtain timespec value for timedwait
            struct timespec t = {.tv_sec = 5, .tv_nsec = 0};
            retlock_timedwait(wait, &t, &ret);
            if (ret == ETIMEDOUT) {
                LOGFN(LNTCE, "tcp_sock_decref() because ETIMEDOUT");
                tcp_sock_decref_unlock(sock);
                return -ETIMEDOUT;
            }
        } else {
            // Wait indefinitely until we are woken
            retlock_wait(wait, &ret);
        }
        tcp_sock_lock(sock);
    }

    tcp_sock_decref_unlock(sock);
    return ret;
}

int tcp_user_send(struct tcp_sock *sock, void *data, size_t len, int flags) {
    if (sock == NULL)
        return -ENOTSOCK;

    // Ensure socket cannot be free'd until this lock is released
    tcp_sock_lock(sock);
    tcp_sock_incref(sock);

    int sent = 0;
    bool send = true;
    switch (sock->state) {
        case TCP_CLOSED:
        case TCP_LISTEN:
            tcp_sock_decref_unlock(sock);
            return -ENOTCONN;
        case TCP_FIN_WAIT_1:
        case TCP_FIN_WAIT_2:
        case TCP_CLOSING:
        case TCP_LAST_ACK:
        case TCP_TIME_WAIT:
            tcp_sock_decref_unlock(sock);
            return -ESHUTDOWN;
        case TCP_SYN_SENT:
        case TCP_SYN_RECEIVED:
            send = false;
        default:
            // ESTABLISHED or CLOSE-WAIT
            break;
    }

    // TODO: Wait on send() for something? (Buffer is full, wait for space?)

    if (len >= rbuf_free(&sock->sndbuf)) {
        tcp_sock_decref_unlock(sock);
        return -ENOSPC;
    }

    // TODO: Write to sndbuf and output directly at the same time
    rbuf_write(&sock->sndbuf, data, len);

    if (send != true) {
        tcp_sock_decref_unlock(sock);
        return sent;
    }

    tcp_sock_unlock(sock);

    // TODO: Signal sending thread and offload segmentation/transmission
    // TODO: Check for MSG_MORE flag and don't trigger for a short while
    while (sent < len) {
        int ret = tcp_send_data(sock, TCP_FLAG_PSH | TCP_FLAG_ACK);
        if (ret < 0) {
            LOGSE(LINFO, "[TCP] tcp_send_data returned", ret);
            sent = ret;
            break;
        }
        sent += ret;
    }
    LOG(LDBUG, "[TCP] Sent %i bytes", sent);

    tcp_sock_decref(sock);
    return sent;
}

int _tcp_user_recv_data(struct tcp_sock *sock, void* out, size_t len);
int tcp_user_recv(struct tcp_sock *sock, void* data, size_t len, int flags) {
    if (!sock)
        return -ENOTSOCK;

    // Ensure socket cannot be free'd until this lock is released
    tcp_sock_lock(sock);
    tcp_sock_incref(sock);

    // recv things

    int ret = 0, err = 0;
    // Last byte sent to the user/copied from sock->recvqueue
    switch (sock->state) {
        case TCP_LISTEN:
        case TCP_SYN_SENT:
        case TCP_SYN_RECEIVED:
            // TODO: Wait here until there is something to recv
            retlock_wait(&sock->wait, &err);
            ret = _tcp_user_recv_data(sock, data, len);
            break;
        case TCP_ESTABLISHED:
        case TCP_FIN_WAIT_1:
        case TCP_FIN_WAIT_2:
            // TODO: Send ACKs for data passed to the user (if specified)
            // Fall-through to CLOSE-WAIT
        case TCP_CLOSE_WAIT:
            tcp_sock_unlock(sock);
            // Return value is # of bytes read
            ret = _tcp_user_recv_data(sock, data, len);
            break;
        default:
            break;
    }

    // Decrement refcount and release sock->lock
    tcp_sock_decref_unlock(sock);

    return ret;
}

int _tcp_user_recv_data(struct tcp_sock *sock, void* out, size_t len) {
    int ret = 0, err = 0;
    unsigned count = 0;     /* # of bytes already copied to out buffer */

    // TODO: Don't return EOF until recv'd up to FIN seqn
    while (count < len) {
        // Assume frames in sock->recvqueue are ordered, but NOT
        // necessarily contiguous. Segments may be missing!

        // First check if there is something to recv
        struct frame *seg = llist_peek(&sock->recvqueue);
        tcp_sock_lock(sock);
        uint32_t irs = sock->tcb.irs;
        tcp_sock_unlock(sock);

        // If there is a segment, ensure it is the next in sequence
        if (seg != NULL) {
            uint32_t seg_seq = ntohl(tcp_hdr(seg)->seqn);
            uint32_t seg_len = frame_data_len(seg);
            uint32_t seg_end = seg_seq + seg_len - 1;

            tcp_sock_lock(sock);
            LOGFN(LTRCE, "sock->recvptr %u, seg_seq %u, seg_end %u",
                sock->recvptr - irs, seg_seq - irs, seg_end - irs);

            // Check if the queued segment has already been passed
            if (tcp_seq_gt(sock->recvptr, seg_end)) {
                LOGFN(LWARN, "sock->recvptr is past seg_end. Skipping segment");

                // Release and remove segment from the queue
                sock->tcb.rcv.wnd += seg_len;
                frame_unlock(seg);
                llist_remove(&sock->recvqueue, seg);
                tcp_sock_unlock(sock);

                // Loop back around to try again
                continue;
            }
        }

        tcp_sock_trylock(sock);
        if (tcp_seq_gt(sock->recvptr, sock->tcb.rcv.nxt))
            LOGFN(LERR, "recvptr > rcv.nxt. This should never happen!");

        // If the next segment isn't in the recvqueue, wait for it
        if (seg == NULL || tcp_seq_geq(sock->recvptr, sock->tcb.rcv.nxt)) {
            if (count > 0) {
                // We have already read some data and the queue is now empty
                // Return back the data to the user
                tcp_sock_unlock(sock);
                break;
            }

            if (sock->state == TCP_CLOSE_WAIT) {
                LOGFN(LTRCE, "[TCP] sock->state hit CLOSE-WAIT. Returning EOF");
                // We have hit EOF. No more data to recv()
                tcp_sock_unlock(sock);
                // Zero signifies EOF
                return 0;
            }

            // Wait for some data then continue when some arrives
            LOGFN(LDBUG, "recvqueue has nothing ready. waiting to be woken up");
            if ((ret = retlock_wait_nolock(&sock->wait, &err)))
                LOGE(LERR, "retlock_wait %s: ", strerror((int) ret));

            LOGFN(LDBUG, "tcp_user_recv woken with %d", err);

            // err is <0 for error, 0 for EOF and >0 for data available
            if (err <= 0)
                // return error or EOF
                return err;

            // Return to start of loop to obtain next segment to recv
            continue;
        } else
            tcp_sock_unlock(sock);

        pthread_mutex_lock(&sock->recvqueue.lock);
        LOGFN(LDBUG, "recvqueue->length = %lu", sock->recvqueue.length);
        pthread_mutex_unlock(&sock->recvqueue.lock);

        size_t space_left = len - count;
        frame_lock(seg, SHARED_RD);
        uint32_t seg_seq = ntohl(tcp_hdr(seg)->seqn);
        uint16_t seg_len = frame_data_len(seg);

        tcp_sock_lock(sock);
        // seg_ofs is the offset within the segment data to start at
        size_t seg_ofs = sock->recvptr - seg_seq;
        // seg_left is the amount of data left in the current seg to read
        size_t seg_left = seg_len - seg_ofs;

        // This shouldn't happen, but just to be sure
        if (!tcp_seq_inwnd(sock->recvptr, seg_seq, seg_len)) {
            LOGFN(LERR, "sock->recvptr is outside seg_seq");
            tcp_sock_unlock(sock);
            continue;
        }
        tcp_sock_unlock(sock);

        LOGFN(LDBUG, "seg len %hu, ptr %lu, space %lu, seg left %lu",
            seg_len, seg_ofs, space_left, seg_left);

        // If there is more data in the segment than space in the buffer
        // then only copy as much as will fit in the buffer
        if (seg_left > space_left) {

            // Copy partial frame and return
            memcpy(out + count, seg->data + seg_ofs, space_left);
            count += space_left;

            // Update last recv position in sock
            tcp_sock_lock(sock);
            sock->recvptr += space_left;
            tcp_sock_unlock(sock);

            // Break from loop and return
            frame_unlock(seg);
            break;
        } else {

            // Copy remainder of frame then dispose of it
            memcpy(out + count, seg->data + seg_ofs, seg_left);
            count += seg_left;

            tcp_sock_lock(sock);

            // Update last recv position in sock
            sock->recvptr += seg_left;

            // Update RCV.WND size after removing consumed segment
            sock->tcb.rcv.wnd += seg_len;

            tcp_sock_unlock(sock);

            // TODO: Check for MSG_PEEK and conditionally don't do this
            // Remove completely consumed frame from the queue
            // If seg isn't sock->recvqueue head, locking isn't working
            // Note: This operation holds it's own lock so a socket RW
            // lock isn't required here
            llist_remove(&sock->recvqueue, seg);
            frame_decref(seg);
        }
    }
    return count;
}

int tcp_user_close(struct tcp_sock *sock) {
    if (!sock)
        return -ENOTSOCK;

    int ret = 0;

    // Ensure socket cannot be free'd until this lock is released
    tcp_sock_lock(sock);
    tcp_sock_incref(sock);

    // TODO: tcp_close() request until all send() calls have completed
    switch (sock->state) {
        case TCP_LISTEN:
            tcp_setstate(sock, TCP_CLOSED);
            tcp_sock_decref(sock);
            break;
        case TCP_SYN_SENT:
            tcp_sock_decref(sock);
            break;
        case TCP_SYN_RECEIVED:
            /* If no SENDs have been issued and there is no pending data to
               send, then form a FIN segment and send it, and enter FIN-WAIT-1
               state; otherwise queue for processing after entering ESTABLISHED
               state. */
            // TODO: Check for pending send() calls
            // Fall through to TCP_ESTABLISHED
        case TCP_ESTABLISHED:
            tcp_sock_incref(sock);
            tcp_setstate(sock, TCP_FIN_WAIT_1);
            tcp_send_finack(sock);
            retlock_wait_bare(&sock->wait, &ret);
            break;
        case TCP_CLOSE_WAIT:
            // TODO: If unsent data, queue sending FIN/ACK on CLOSING
            tcp_sock_incref(sock);
            // RFC 1122: Section 4.2.2.20 (a)
            // TCP event processing corrections
            // https://tools.ietf.org/html/rfc1122#page-93
            tcp_setstate(sock, TCP_LAST_ACK);
            tcp_send_finack(sock);
            retlock_wait_bare(&sock->wait, &ret);
            break;
        case TCP_CLOSING:
        case TCP_LAST_ACK:
        case TCP_TIME_WAIT:
            // Connection already closing
            tcp_sock_decref(sock);
            return -EALREADY;
        case TCP_CLOSED:
            tcp_sock_decref(sock);
            return -ENOTCONN;
        default:
            break;
    }

    tcp_sock_decref_unlock(sock);
    return ret;
}

int tcp_user_listen(struct tcp_sock *sock, size_t backlog) {
    if (sock == NULL)
        return -ENOTSOCK;

    // Move socket to end of socket list
    // Listening sockets should be the last thing to looked-up
    pthread_mutex_lock(&tcp_sockets.lock);
    llist_remove_nolock(&tcp_sockets, sock);
    llist_append_nolock(&tcp_sockets, sock);
    pthread_mutex_unlock(&tcp_sockets.lock);

    tcp_sock_lock(sock);

    tcp_setstate(sock, TCP_LISTEN);
    sock->passive = malloc(sizeof(struct tcp_passive));
    *sock->passive = (struct tcp_passive) {
        .maxbacklog = backlog,
        .backlog = LLIST_INITIALISER,
    };

    tcp_sock_unlock(sock);

    return 0;
}

int tcp_user_accept(struct tcp_sock *sock, struct tcp_sock **client) {
    if (sock == NULL)
        return -ENOTSOCK;

    tcp_sock_lock(sock);
    // EINVAL: Socket is not listening for connections
    if (client == NULL || sock->passive == NULL)
        return -EINVAL;

    // Initialise value to NULL to prevent unitialised errors
    // We can't/shouldn't assume the user will initialise the memory
    *client = NULL;

    while (*client == NULL) {

        // Check to see if there is an established socket ready to accept
        if ((*client = llist_pop(&sock->passive->backlog)) != NULL) {
            tcp_sock_lock(*client);
            switch ((*client)->state) {
                case TCP_LISTEN:
                case TCP_SYN_SENT:
                case TCP_SYN_RECEIVED:
                    // Connection is not established yet. Re-queue it for now
                    llist_append(&sock->passive->backlog, *client);

                    // Attempt to get another client
                    tcp_sock_unlock(*client);
                    *client = NULL;
                    continue;

                case TCP_FIN_WAIT_1:
                case TCP_FIN_WAIT_2:
                case TCP_CLOSING:
                case TCP_CLOSED:
                case TCP_LAST_ACK:
                case TCP_TIME_WAIT:
                    LOGFN(LWARN, "tcp_user_accept client in invalid state: %s",
                            tcp_strstate((*client)->state));
                    tcp_sock_unlock(*client);
                    *client = NULL;
                    continue;

                case TCP_ESTABLISHED:
                case TCP_CLOSE_WAIT:
                    // Client is in valid state and ready to communicate
                    LOGFN(LNTCE, "[TCP] Accepting client %p from backlog", *client);
                    tcp_sock_unlock(*client);
                    break;
            }
            break;
        }

        // TODO: Check for O_NONBLOCK and return EWOULDBLOCK in tcp_user_accept

        LOGFN(LNTCE, "[TCP] No connections ready to be accepted. Waiting..");

        retlock_wait_bare(&sock->wait, NULL);
    }

    tcp_sock_unlock(sock);
    return 0;
}
