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

    if (sock == NULL) {
        return -ENOTSOCK;
    }

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
            tcp_sock_decref(sock);
            return -EISCONN;
        case TCP_SYN_SENT:
        case TCP_SYN_RECEIVED:
            LOGFN(LNTCE, "tcp_sock_decref() because EALREADY");
            tcp_sock_decref(sock);
            return -EALREADY;
        default:
            break;
    }

    sock->opentype = TCP_ACTIVE_OPEN;
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
        tcp_sock_decref(sock);
        return ret;
    }

    tcp_setstate(sock, TCP_SYN_SENT);

    // Wait for the connection to be established
    while (sock->state != TCP_ESTABLISHED && ret >= 0) {

        // Take reference to openwait before releasing lock
        // Hopefully this does not incur a race condition :/
        retlock_t *wait = &sock->openwait;
        // Unlock before going to sleep
        tcp_sock_unlock(sock);

        if (sock->inet.flags & O_NONBLOCK) {
            // TODO: Obtain timespec value for timedwait
            struct timespec t = {.tv_sec = 5, .tv_nsec = 0};
            retlock_timedwait(wait, &t, &ret);
            if (ret == ETIMEDOUT) {
                LOGFN(LNTCE, "tcp_sock_decref() because ETIMEDOUT");
                tcp_sock_decref(sock);
                return -ETIMEDOUT;
            }
        } else {
            // Wait indefinitely until we are woken
            retlock_wait(wait, &ret);
        }
        tcp_sock_lock(sock);
    }

    tcp_sock_decref(sock);
    return ret;
}

int tcp_user_send(struct tcp_sock *sock, void *data, size_t len, int flags) {
    if (sock == NULL) {
        return -ENOTSOCK;
    }

    // Ensure socket cannot be free'd until this lock is released
    tcp_sock_lock(sock);
    tcp_sock_incref(sock);

    int sent = 0;
    bool send = true;
    switch (sock->state) {
        case TCP_CLOSED:
        case TCP_LISTEN:
            tcp_sock_decref(sock);
            return -ENOTCONN;
        case TCP_FIN_WAIT_1:
        case TCP_FIN_WAIT_2:
        case TCP_CLOSING:
        case TCP_LAST_ACK:
        case TCP_TIME_WAIT:
            tcp_sock_decref(sock);
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
        tcp_sock_decref(sock);
        return -ENOSPC;
    }

    // TODO: Write to sndbuf and output directly at the same time
    rbuf_write(&sock->sndbuf, data, len);

    if (send != true) {
        tcp_sock_decref(sock);
        return sent;
    }

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

int tcp_user_recv(struct tcp_sock *sock, void* data, size_t len, int flags) {
    if (!sock)
        return -ENOTSOCK;

    // Ensure socket cannot be free'd until this lock is released
    tcp_sock_lock(sock);
    tcp_sock_incref(sock);

    // recv things

    // Decrement refcount and release sock->lock
    tcp_sock_decref(sock);

    return 0;
}

int tcp_user_close(struct tcp_sock *sock) {
    if (!sock)
        return -ENOTSOCK;

    // Ensure socket cannot be free'd until this lock is released
    tcp_sock_lock(sock);
    tcp_sock_incref(sock);

    // TODO: tcp_close() request until all send() calls have completed
    switch (sock->state) {
        case TCP_LISTEN:
            tcp_setstate(sock, TCP_CLOSED);
            tcp_sock_cleanup(sock);
            break;
        case TCP_SYN_SENT:
            tcp_sock_cleanup(sock);
            break;
        case TCP_SYN_RECEIVED:
            /* If no SENDs have been issued and there is no pending data to
               send, then form a FIN segment and send it, and enter FIN-WAIT-1
               state; otherwise queue for processing after entering ESTABLISHED
               state. */
            // TODO: Check for pending send() calls
            // Fall through to TCP_ESTABLISHED
        case TCP_ESTABLISHED:
            tcp_send_finack(sock);
            tcp_setstate(sock, TCP_FIN_WAIT_1);
            break;
        case TCP_CLOSE_WAIT:
            tcp_send_finack(sock);
            tcp_setstate(sock, TCP_CLOSED);
            break;
        case TCP_CLOSING:
        case TCP_LAST_ACK:
        case TCP_TIME_WAIT:
            // Connection already closing
            tcp_sock_decref(sock);
            tcp_sock_unlock(sock);
            return -EALREADY;
        case TCP_CLOSED:
            tcp_sock_decref(sock);
            tcp_sock_unlock(sock);
            return -ENOTCONN;
        default:
            break;
    }

    tcp_sock_decref(sock);
    return 0;
}
