#include <stdlib.h>
#include <errno.h>

#include <netstack/tcp/tcp.h>

/*
 * As defined in RFC 793: Functional Specification (pg 54 - 64)
 * https://tools.ietf.org/html/rfc793#page-54
 */

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
        return ENOTSOCK;
    }

    switch (sock->state) {
        case TCP_ESTABLISHED:
        case TCP_FIN_WAIT_1:
        case TCP_FIN_WAIT_2:
        case TCP_LAST_ACK:
        case TCP_CLOSING:
        case TCP_CLOSE_WAIT:
            return EISCONN;
        case TCP_SYN_SENT:
        case TCP_SYN_RECEIVED:
            return EALREADY;
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

    int ret = tcp_send_syn(sock);

    tcp_setstate(sock, TCP_SYN_SENT);

    // Wait indefinitely for the connection to be established
    while (sock->state != TCP_ESTABLISHED) {
        // TODO: Check for O_NONBLOCK
        if (false) {
            struct timespec t = {.tv_sec = 5, .tv_nsec = 0};
            int e = pthread_cond_timedwait(&sock->openwait, &sock->openlock, &t);
            if (e == ETIMEDOUT) {
                tcp_free_sock(sock);
                return ETIMEDOUT;
            }
        } else {
            pthread_cond_wait(&sock->openwait, &sock->openlock);
        }
    }

    return ret;
}

int tcp_user_close(struct tcp_sock *sock) {
    if (!sock)
        return -ENOTSOCK;

    // TODO: tcp_close() request until all send() calls have completed
    switch (sock->state) {
        case TCP_LISTEN:
            // TODO: Interrupt waiting recv() calls with -ECONNABORTED
            tcp_setstate(sock, TCP_CLOSED);
            tcp_free_sock(sock);
            break;
        case TCP_SYN_SENT:
            tcp_free_sock(sock);
            // TODO: Interrupt waiting send()/recv() calls with -ECONNABORTED
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
            return EALREADY;
        case TCP_CLOSED:
            return ENOTCONN;
        default:
            break;
    }
    return 0;
}