#include <stdlib.h>
#include <errno.h>
#include <sys/param.h>
#include <netinet/in.h>

#define NETSTACK_LOG_UNIT "TCP"
#include <netstack/tcp/tcp.h>
#include <netstack/lock/retlock.h>
#include <netstack/tcp/retransmission.h>

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
            LOG(LNTCE, "tcp_sock_decref() because EISCONN");
            tcp_sock_decref_unlock(sock);
            return -EISCONN;
        case TCP_SYN_SENT:
        case TCP_SYN_RECEIVED:
            LOG(LNTCE, "tcp_sock_decref() because EALREADY");
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

    // Ensure the state is SYN-SENT _before_ calling tcp_send_syn() so that
    // the correct retransmit timeout function is used
    tcp_setstate(sock, TCP_SYN_SENT);

    int ret;
    if ((ret = tcp_send_syn(sock)) < 0) {
        LOG(LNTCE, "tcp_sock_decref() because tcp_send_syn() err");
        tcp_sock_decref_unlock(sock);
        return ret;
    }

    // Wait for the connection to be established
    while (sock->state != TCP_ESTABLISHED && ret >= 0) {

        // TODO: Check for O_NONBLOCK
        if (false) {
            // TODO: Obtain timespec value for timedwait
            struct timespec t = {.tv_sec = 5, .tv_nsec = 0};
            retlock_timedwait(&sock->wait, &t, &ret);
            if (ret == ETIMEDOUT) {
                LOG(LNTCE, "tcp_sock_decref() because ETIMEDOUT");
                tcp_sock_decref_unlock(sock);
                return -ETIMEDOUT;
            }
        } else {
            // Wait indefinitely until we are woken
            retlock_wait_bare(&sock->wait, &ret);
        }
    }

    tcp_sock_decref_unlock(sock);
    return ret;
}

#define tcp_user_send_state_check(sock) \
    switch ((sock)->state) { \
        case TCP_CLOSED: \
        case TCP_LISTEN: \
        case TCP_SYN_SENT: \
        case TCP_SYN_RECEIVED: \
            tcp_sock_decref_unlock(sock); \
            return -ENOTCONN; \
        case TCP_FIN_WAIT_1: \
        case TCP_FIN_WAIT_2: \
        case TCP_CLOSING: \
        case TCP_LAST_ACK: \
        case TCP_TIME_WAIT: \
            tcp_sock_decref_unlock(sock); \
            return -ESHUTDOWN; \
        default: \
            /* ESTABLISHED or CLOSE-WAIT */ \
            break; \
    } \

int tcp_user_send(struct tcp_sock *sock, void *data, size_t len, int flags) {
    if (sock == NULL)
        return -ENOTSOCK;

    // Ensure socket cannot be free'd until this lock is released
    tcp_sock_incref(sock);
    tcp_sock_lock(sock);

    int sent = 0;

    // Ensure the socket is in a valid sending state and return if not
    tcp_user_send_state_check(sock);

    // TODO: Write to sndbuf and output directly at the same time
    // TODO: Limit the size of the send buffer. Block if the buffer is full
    seqbuf_write(&sock->sndbuf, data, len);

    // TODO: Signal sending thread and offload segmentation/transmission
    // TODO: Check for MSG_MORE flag and don't trigger for a short while
    while (sent < len) {

        // Check every send iteration too, just to make
        // sure the state hasn't changed in between
        tcp_user_send_state_check(sock);

        // Ensure there is enough space in the remote rcv.wnd
        // Take into account those unacknowledged segments that are in-flight
        size_t inflight_sum = 0;
        for_each_llist(&sock->unacked) {
            struct tcp_seq_data *unacked = llist_elem_data();
            inflight_sum += unacked->len;
        }

        size_t space = MAX(0, ((int32_t) sock->tcb.snd.wnd) - inflight_sum);
        if (space <= 0) {

            // Don't wait if socket is non-blocking
            if (sock->inet.flags & O_NONBLOCK) {
                tcp_sock_decref_unlock(sock);
                return -EWOULDBLOCK;
            }

            LOG(LINFO, "no space in SND.WND. waiting for an incoming ACK");

            // We assume the remote send window is full so wait for an ACK
            pthread_cond_wait(&sock->waitack, &sock->wait.lock);

            // Woken up; we should re-check our state before sending
            LOG(LINFO, "woken as ACK arrived. attempting to send again");
            continue;
        }

        uint32_t seqn = sock->tcb.snd.nxt;

        // There is space in the send window- unlock and get the data out!
        tcp_sock_unlock(sock);

        // Send at most the space left in the SND.WND
        int ret = tcp_send_data(sock, seqn, space, 0);
        if (ret <= 0) {
            LOGSE(LINFO, "tcp_send_data returned", -ret);
            sent = ret;
            break;
        }
        sent += ret;
        LOG(LVERB, "Sent %i bytes (%i/%zu)", ret, sent, len);

        // Lock as we return to the start of the loop again
        tcp_sock_lock(sock);
    }
    if (sent > 0)
        LOG(LDBUG, "Sent in total %i bytes", sent);

    if (sent != len)
        LOG(LCRIT, "Didn't send everything in the buffer :( %d != %zu", sent, len);

    tcp_sock_decref_unlock(sock);

    // Notify that we sent it all, even though the segments never actually got
    // sent. Retransmissions will pick up the pieces
    // TODO: Rewind the send buffer to the amount of data we actually sent
    return (int) len;
}

int tcp_user_recv(struct tcp_sock *sock, void* out, size_t len, int flags) {
    if (!sock)
        return -ENOTSOCK;

    // Ensure socket cannot be free'd until this lock is released
    tcp_sock_incref(sock);

    int ret = 0, err = 0;
    unsigned count = 0;     /* # of bytes already copied to out buffer */

    // TODO: Don't return EOF until recv'd up to FIN seqn
    while (count < len) {
        // Assume frames in sock->recvqueue are ordered, but NOT
        // necessarily contiguous. Segments may be missing!

        // IMPORTANT LOCKING NOTE:
        // Take the socket lock and hold it UNTIL all operations to
        // sock->recvptr, sock->recvqueue and tcb->rcv.wnd have completed
        // to ensure atomicity.
        // Reading, unlocking, locking then writing is VERY VERY BAD
        tcp_sock_lock(sock);

        // First check if there is something to recv
        struct frame *seg = llist_peek(&sock->recvqueue);
        uint32_t irs = sock->tcb.irs;

        // If there is a segment, ensure it is the next in sequence
        if (seg != NULL) {
            uint32_t seg_seq = ntohl(tcp_hdr(seg)->seqn);
            uint32_t seg_len = frame_data_len(seg);
            uint32_t seg_end = seg_seq + seg_len - 1;

            LOG(LTRCE, "sock->recvptr %u, seg_seq %u, seg_end %u",
                sock->recvptr - irs, seg_seq - irs, seg_end - irs);

            // Check if the queued segment has already been passed
            if (tcp_seq_gt(sock->recvptr, seg_end)) {
                LOG(LWARN, "sock->recvptr is past seg_end. Skipping segment");

                // Release and remove segment from the queue
                sock->tcb.rcv.wnd += seg_len;
                tcp_sock_unlock(sock);
                frame_unlock(seg);
                llist_remove(&sock->recvqueue, seg);

                // Loop back around to try again
                continue;
            }
        }

        if (tcp_seq_gt(sock->recvptr, sock->tcb.rcv.nxt))
            LOG(LERR, "recvptr > rcv.nxt. This should never happen!");

        // If the next segment isn't in the recvqueue, wait for it
        if (seg == NULL || tcp_seq_geq(sock->recvptr, sock->tcb.rcv.nxt)) {
            if (count > 0) {
                tcp_sock_unlock(sock);

                // We have already read some data and the queue is now empty
                // Return back the data to the user
                ret = count;
                goto decref_and_return;
            }

            switch (sock->state) {
                case TCP_CLOSE_WAIT:
                case TCP_LAST_ACK:
                case TCP_TIME_WAIT:
                    LOG(LTRCE, "sock->state hit %s. Returning EOF",
                        tcp_strstate(sock->state));

                    tcp_sock_unlock(sock);

                    // We have hit EOF. No more data to recv()
                    // Zero signifies EOF
                    ret = 0;
                    goto decref_and_return;
                default:
                    break;
            }

            // Wait for some data then continue when some arrives
            LOG(LDBUG, "recvqueue has nothing ready. waiting to be woken up");
            if ((ret = retlock_wait_bare(&sock->wait, &err)))
                LOGE(LERR, "retlock_wait %s: ", strerror((int) ret));

            LOG(LDBUG, "tcp_user_recv woken with %d", err);
            tcp_sock_unlock(sock);

            // Don't return EOF if 0 here, check properly above

            // err is <0 for error
            if (err < 0) {
                ret = err;
                goto decref_and_return;
            }

            // Return to start of loop to obtain next segment to recv
            continue;
        }

        pthread_mutex_lock(&sock->recvqueue.lock);
        LOG(LDBUG, "recvqueue->length = %lu", sock->recvqueue.length);
        pthread_mutex_unlock(&sock->recvqueue.lock);

        size_t space_left = len - count;
        frame_lock(seg, SHARED_RD);
        uint32_t seg_seq = ntohl(tcp_hdr(seg)->seqn);
        uint16_t seg_len = frame_data_len(seg);

        // seg_ofs is the offset within the segment data to start at
        size_t seg_ofs = sock->recvptr - seg_seq;
        // seg_left is the amount of data left in the current seg to read
        size_t seg_left = seg_len - seg_ofs;

        // This shouldn't happen, but just to be sure
        if (!tcp_seq_inwnd(sock->recvptr, seg_seq, seg_len)) {
            LOG(LERR, "sock->recvptr is outside seg_seq");
            tcp_sock_unlock(sock);
            continue;
        }

        LOG(LDBUG, "seg len %hu, ptr %lu, space %lu, seg left %lu",
            seg_len, seg_ofs, space_left, seg_left);

        // If there is more data in the segment than space in the buffer
        // then only copy as much as will fit in the buffer
        if (seg_left > space_left) {

            // Update last recv position in sock
            sock->recvptr += space_left;

            // Maintain the lock around reading and writing to recvptr
            tcp_sock_unlock(sock);

            // Copy partial frame and return
            memcpy(out + count, seg->data + seg_ofs, space_left);
            count += space_left;

            // Break from loop and return
            frame_unlock(seg);
            break;
        } else {

            // Update last recv position in sock
            sock->recvptr += seg_left;

            // Update RCV.WND size after removing consumed segment
            sock->tcb.rcv.wnd += seg_len;

            // Remove completely consumed frame from the queue
            // If seg isn't sock->recvqueue head, locking isn't working
            // Note: This operation holds it's own lock so a socket RW
            // lock isn't required here
            llist_remove(&sock->recvqueue, seg);

            tcp_sock_unlock(sock);

            // Copy remainder of frame then dispose of it
            memcpy(out + count, seg->data + seg_ofs, seg_left);
            count += seg_left;

            // TODO: Check for MSG_PEEK and conditionally don't do this
            frame_decref(seg);
        }
    }
    ret = count;

decref_and_return:
    tcp_sock_decref(sock);
    return ret;
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
            tcp_setstate(sock, TCP_FIN_WAIT_1);
            tcp_send_finack(sock);
            retlock_wait_bare(&sock->wait, &ret);
            break;
        case TCP_CLOSE_WAIT:
            // TODO: If unsent data, queue sending FIN/ACK on CLOSING
            // RFC 1122: Section 4.2.2.20 (a)
            // TCP event processing corrections
            // https://tools.ietf.org/html/rfc1122#page-93
            tcp_setstate(sock, TCP_LAST_ACK);
            tcp_send_finack(sock);

            // Wait for the connection to be closed before returning
            while (!(sock->state == TCP_TIME_WAIT || sock->state == TCP_CLOSED))
                retlock_wait_bare(&sock->wait, &ret);

            break;
        case TCP_CLOSING:
        case TCP_LAST_ACK:
        case TCP_TIME_WAIT:
            // Connection already closing
            ret = -EALREADY;
            break;
        case TCP_CLOSED:
            ret = -ENOTCONN;
            break;
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
                    LOG(LWARN, "tcp_user_accept client not yet established"
                            " %p. re-queuing..", *client);
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
                    LOG(LWARN, "tcp_user_accept client in invalid state: %s",
                            tcp_strstate((*client)->state));
                    tcp_sock_unlock(*client);
                    *client = NULL;
                    continue;

                case TCP_ESTABLISHED:
                case TCP_CLOSE_WAIT:
                    // Client is in valid state and ready to communicate
                    LOG(LNTCE, "Accepting client %p from backlog", *client);
                    // Remove non-blocking flag now that the user has control
                    (*client)->inet.flags &= ~O_NONBLOCK;
                    tcp_sock_unlock(*client);
                    break;
            }
            break;
        }

        // TODO: Check for O_NONBLOCK and return EWOULDBLOCK in tcp_user_accept

        LOG(LNTCE, "No connections ready to be accepted. Waiting..");

        retlock_wait_bare(&sock->wait, NULL);
    }

    tcp_sock_unlock(sock);
    return 0;
}
